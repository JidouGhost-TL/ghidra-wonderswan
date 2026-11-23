#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Consume pinned public inputs in a new disposable directory."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from urllib.parse import quote, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, build_opener
import zipfile

here = Path(__file__).resolve().parent
example = here.parents[1] / "examples/banked-call"
pins = json.loads((here / "inputs.json").read_text())
candidate_commit = "e1ebe4beb2d46889ddcd68c5b9f6bef58edf4160"
candidate_sha256 = {
    "v30mz": "a13834a0c8c19a6e8189d7e16496eec577ed6db8c3020d0a5fe4ea4bd0fbf2c9",
    "wonderswan": "c25db5e56e0555c371f034d125d0c1d40ba22affb4777ecf2b4e657c019254e7",
}
platforms = {("Linux", "x86_64"): "Linux-x64", ("Windows", "AMD64"): "Windows-x64",
             ("Darwin", "arm64"): "Darwin-arm64", ("Darwin", "x86_64"): "Darwin-x64"}
redirect_hosts = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
examples = {
    "make_cartridges.py": "ef2585d2342a6a259421897f0bb5363836a6b77a80feb2f5b676bbc765257bc0",
    "ConfigureBankEvidence.java": "4c084c94d3ad1deb3de4cb14d1564e7101baf4a9420b668a223184bf8cd1dcfb",
    "VerifyBankedCall.java": "9dddfc620a863e865a9ff97c652cda21ba28f60e79489fb316425f628a1a7839",
}


def gradle_failure(log):
    """Interpret a bounded tail; only a fixed category can leave the runner."""
    if log is None or not log.is_file():
        return "gradle_other"
    try:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 64 * 1024))
            tail = stream.read(64 * 1024).decode("utf-8", errors="replace").lower()
    except OSError:
        return "gradle_other"
    for reason, flags in (
        ("disk_full", ("no space left on device",)),
        ("gradle_checksum", ("verification of gradle distribution failed", "checksum verification failed")),
        ("gradle_download", ("could not install gradle distribution", "filenotfoundexception: https://",
                              "could not download gradle", "download timed out")),
        ("gradle_task", ("cannot locate tasks that match", "task 'buildnatives' not found")),
        ("gradle_toolchain", ("no tool chain is available", "no toolchain is available",
                               "no compatible toolchains", "xcrun: error:")),
        ("gradle_link", ("linker command failed", "undefined symbols for architecture",
                         "ld: library not found", "failed while linking")),
        ("gradle_compile", ("compilation failed", "failed while compiling", "fatal error:")),
    ):
        if any(flag in tail for flag in flags):
            return reason
    return "gradle_other"


class Diagnostic:
    def __init__(self, platform_name):
        self.platform = platform_name
        self.stage = "preflight"
        self.item = None
        self.log = None

    def emit(self, status, reason=None):
        record = {"platform": self.platform, "stage": self.stage, "status": status}
        if self.item is not None:
            record["item"] = self.item
        if reason is not None:
            record["reason"] = reason
        print("PUBLIC_GHIDRA_STAGE " + json.dumps(record, separators=(",", ":")), flush=True)

    def begin(self, stage, item=None, log=None):
        self.stage, self.item, self.log = stage, item, log
        self.emit("begin")

    def fail(self, error):
        if isinstance(error, subprocess.TimeoutExpired):
            reason = "process_timeout"
        elif isinstance(error, TimeoutError):
            reason = "io_timeout"
        elif isinstance(error, HTTPError):
            reason = "http_error"
        elif isinstance(error, URLError):
            reason = "network_error"
        elif isinstance(error, FileNotFoundError):
            reason = "missing_file"
        elif isinstance(error, (zipfile.BadZipFile, tarfile.TarError)):
            reason = "archive_format"
        elif isinstance(error, OSError) and error.errno == errno.ENOSPC:
            reason = "disk_full"
        elif isinstance(error, subprocess.CalledProcessError):
            reason = gradle_failure(self.log) if self.stage.startswith("gradle_") else "process_exit"
        elif isinstance(error, (RuntimeError, ValueError)):
            reason = "checked_invariant"
        else:
            reason = "other_error"
        self.emit("failed", reason)


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_pins():
    archive_pins = [pins["ghidra"], pins["extension_manifest"], *pins["extensions"]]
    hashes = [record[3] for record in archive_pins]
    hashes.extend(record[1] for record in pins["jdk"].values())
    hashes.extend(pins["fixtures"].values())
    hashes.extend(examples.values())
    hashes.append(pins["gradle_sha256"])
    require(all(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) for sha in hashes),
            "Release pins must be 64 lowercase hexadecimal SHA-256 characters")


class PublicReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        require(target.scheme == "https" and target.netloc in redirect_hosts,
                f"Unexpected binary download destination {target.scheme}://{target.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(spec, downloads, cache):
    repository, tag, name, sha = spec
    target = downloads / name
    if cache and (cache / name).is_file():
        shutil.copyfile(cache / name, target)
    else:
        url = f"https://github.com/{repository}/releases/download/{quote(tag, safe='')}/{name}"
        with build_opener(PublicReleaseRedirect()).open(url, timeout=90) as src, target.open("xb") as dst:
            shutil.copyfileobj(src, dst)
    require(digest(target) == sha, f"Wrong SHA-256 for {name}")
    return target


def unzip(archive, dest):
    with zipfile.ZipFile(archive) as z:
        written = []
        for entry in z.infolist():
            name = entry.filename
            relative = PurePosixPath(name)
            mode = entry.external_attr >> 16
            require(relative.parts and not relative.anchor and not PureWindowsPath(name).anchor
                    and ".." not in relative.parts and ":" not in name and "\\" not in name
                    and not stat.S_ISLNK(mode), f"Unexpected ZIP member {name}")
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if entry.is_dir():
                target.mkdir(exist_ok=True)
                continue
            with z.open(entry) as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            if os.name != "nt" and mode & 0o111:
                target.chmod(0o755)
            written.append(relative)
    return written


def run(command, env, log, cwd=None, timeout=240):
    args = [str(x) for x in command]
    if os.name == "nt" and args[0].endswith(".bat"):
        require(all(not re.search(r'[%!&|<>^"\r\n]', token) for token in args), "Unsafe batch path")
        quoted = " ".join(f'"{token}"' for token in args)
        args = f'cmd.exe /d /s /c "{quoted}"'
    with log.open("xb") as stream:
        subprocess.run(args, env=env, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                       check=True, timeout=timeout)
    return log.read_text(encoding="utf-8", errors="replace")


def paths(output, host):
    home = output / "home"
    ghidra = output / "ghidra_12.1.3_PUBLIC"
    suffix = ".exe" if host == "Windows-x64" else ""
    java = list((output / "jdk").glob(f"*/bin/java{suffix}"))
    if host.startswith("Darwin"):
        java = list((output / "jdk").glob("*/Contents/Home/bin/java"))
    require(len(java) == 1, "Expected one pinned JDK")
    jdk = java[0].parents[1]
    for folder in ("settings", "cache", "tmp", "gradle"):
        (home / folder).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, JAVA_HOME=str(jdk), JAVA_HOME_OVERRIDE=str(jdk),
               PATH=str(jdk / "bin") + os.pathsep + os.environ["PATH"],
               GHIDRA_INSTALL_DIR=str(ghidra), GHIDRA_HEADLESS_MAXMEM="2G", GHIDRA_GUI_MAXMEM="2G",
               XDG_CONFIG_HOME=str(home / "settings"), XDG_CACHE_HOME=str(home / "cache"),
               GRADLE_USER_HOME=str(home / "gradle"))
    if host == "Windows-x64":
        env["USERPROFILE"] = str(home)
        env["APPDATA"] = str(home / "settings")
        env["LOCALAPPDATA"] = str(home / "cache")
    options = {"user.home":home, "application.settingsdir":home/"settings",
               "application.cachedir":home/"cache", "application.tempdir":home/"tmp",
               "java.io.tmpdir":home/"tmp"}
    env["JAVA_TOOL_OPTIONS"] = " ".join(f'"-D{key}={value}"' for key, value in options.items())
    for key in ("JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GHIDRA_JAVA_OPTIONS",
                "GHIDRA_HEADLESS_JAVA_OPTIONS", "GHIDRA_GUI_JAVA_OPTIONS"):
        env.pop(key, None)
    return ghidra, java[0], home, env


def require_mach_executable(description, host):
    arch = "arm64" if host == "Darwin-arm64" else "x86_64"
    prefix = re.escape(f"Mach-O 64-bit executable {arch}")
    require(re.match(prefix + r"(?=$|[\s,])", description.strip()),
            "Wrong native decompiler executable architecture")


def pin_gradle(gradle):
    wrapper = gradle / "gradle-wrapper.properties"
    text = wrapper.read_text()
    require("gradle-9.6.1-bin.zip" in text and "distributionSha256Sum=" not in text, "Gradle pin drift")
    wrapper.write_text(text + f'\ndistributionSha256Sum={pins["gradle_sha256"]}\n')


def stage_candidate_source(output, checkout, diagnostic):
    diagnostic.begin("candidate_source")
    readback = run(["git", "-C", checkout, "rev-parse", "HEAD"], os.environ, output / "candidate-source.log")
    require(readback.strip() == candidate_commit, "Unexpected candidate source commit")
    archive = output / "candidate-source.zip"
    run(["git", "-C", checkout, "archive", "--format=zip", "-o", archive, candidate_commit],
        os.environ, output / "candidate-source-archive.log")
    source = output / "candidate-source"
    unzip(archive, source)
    return source


def candidate_archive_pins():
    return {f"{module}-candidate.zip": sha for module, sha in candidate_sha256.items()}


def build_candidate(output, source, host, ghidra, env, diagnostic):
    gradle = ghidra / "support" / "gradle"
    build_env = dict(env)
    for key in ("JAVA_OPTS", "GRADLE_OPTS"):
        build_env.pop(key, None)
    args = []
    if host == "Windows-x64":
        # This immutable source predates the platform-aware compileSleigh task.
        # Compile with the equivalent stock batch entry point before packaging.
        log = output / "candidate-sleigh.log"
        diagnostic.begin("candidate_sleigh", log=log)
        run([ghidra / "support" / "sleigh.bat", "-a", "."], build_env, log,
            cwd=source / "v30mz" / "data" / "languages", timeout=180)
        require((source / "v30mz" / "data" / "languages" / "v30mz.sla").is_file(),
                "Candidate Sleigh compilation produced no language")
        args = ["--exclude-task", ":v30mz:compileSleigh"]

    wrapper = gradle / ("gradlew.bat" if host == "Windows-x64" else "gradlew")
    log = output / "candidate-extension-build.log"
    diagnostic.begin("gradle_candidate_build", log=log)
    run([wrapper, "--no-daemon", "--offline", "--project-dir", source, "buildExtension", *args],
        build_env, log, timeout=600)
    diagnostic.begin("candidate_archive_digests")
    verified = []
    for module, sha in candidate_sha256.items():
        matches = list((source / module / "dist").glob(f"ghidra_12.1.3_PUBLIC_*_{module}.zip"))
        require(len(matches) == 1 and digest(matches[0]) == sha, "Candidate archive SHA-256 differs")
        verified.append((module, matches[0]))
    extensions = []
    for module, archive in verified:
        dest = output / "downloads" / f"{module}-candidate.zip"
        archive.rename(dest)
        extensions.append(dest)
    return extensions


def prepare(output, host, cache, diagnostic, *, candidate_checkout=None):
    diagnostic.begin("validate_release_pins")
    validate_pins()
    diagnostic.begin("fresh_directory")
    output.mkdir()
    downloads = output/"downloads"
    downloads.mkdir()
    source = stage_candidate_source(output, candidate_checkout, diagnostic) if candidate_checkout is not None else None
    diagnostic.begin("fetch_ghidra")
    ghidra = download(pins["ghidra"], downloads, cache)
    if source is None:
        diagnostic.begin("fetch_extensions")
        extensions = [download(spec, downloads, cache) for spec in pins["extensions"]]
        release_checksums = download(pins["extension_manifest"], downloads, cache)
        expected = {name: sha for _, _, name, sha in pins["extensions"]}
        require(dict((name, sha) for sha, name in (line.split() for line in
                release_checksums.read_text().splitlines())) == expected, "Published manifest disagrees")
    else:
        expected = candidate_archive_pins()
    diagnostic.begin("fetch_jdk")
    jdk = download(["adoptium/temurin21-binaries", "jdk-21.0.13.1+2", *pins["jdk"][host]], downloads, cache)
    diagnostic.begin("unpack_ghidra")
    unzip(ghidra, output)
    diagnostic.begin("unpack_jdk")
    if jdk.suffix == ".zip":
        unzip(jdk, output/"jdk")
    else:
        with tarfile.open(jdk) as archive:
            archive.extractall(output/"jdk", filter="data")
    diagnostic.begin("public_fixture")
    scripts = output/"example"
    scripts.mkdir()
    for name, sha in examples.items():
        # Git may materialize CRLF on Windows. The staged scripts use the exact pinned blob bytes.
        content = (example/name).read_bytes().replace(b"\r\n", b"\n")
        require(hashlib.sha256(content).hexdigest() == sha, f"Public example input changed: {name}")
        (scripts/name).write_bytes(content)
    run([sys.executable, scripts/"make_cartridges.py", output/"roms"], os.environ, output/"fixture.log")
    require({item.name:digest(item) for item in (output/"roms").glob("*.ws")} == pins["fixtures"],
            "The public synthetic cartridges changed")
    diagnostic.begin("java_version")
    ghidra, java, home, env = paths(output, host)
    version = run([java, "-XshowSettings:properties", "-version"], env, output/"java.log")
    arches = ("aarch64",) if host.endswith("arm64") else ("amd64","x86_64")
    require("21.0.13.1+2" in version and any(f"os.arch = {arch}\n" in version for arch in arches),
            "Wrong native JDK")
    gradle = ghidra / "support" / "gradle"
    if host.startswith("Darwin"):
        diagnostic.begin("mac_toolchain")
        pin_gradle(gradle)
        run(["/usr/bin/xcrun", "--find", "clang"], env, output/"clang-path.log")
        run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env, output/"macos-sdk.log")
        developer = env.get("DEVELOPER_DIR")
        if developer is None:
            developer = run(["/usr/bin/xcode-select", "-p"], env, output/"developer-dir.log").strip()
        developer = Path(developer)
        if developer.suffix == ".app":
            developer = developer / "Contents/Developer"
        if (developer / "usr/bin/xcodebuild").is_file():
            run(["/usr/bin/xcodebuild", "-version"], env, output/"xcode.log")
        bootstrap_log = output/"gradle-bootstrap.log"
        diagnostic.begin("gradle_bootstrap", log=bootstrap_log)
        run([gradle/"gradlew", "--no-daemon", "--version"], env, bootstrap_log, gradle, timeout=300)
        native_log = output/"native-build.log"
        diagnostic.begin("gradle_native_build", log=native_log)
        run([gradle/"gradlew", "--no-daemon", "buildNatives"], env, native_log, gradle, timeout=1800)
    diagnostic.begin("native_executable")
    ids = {"Linux-x64":"linux_x86_64", "Windows-x64":"win_x86_64",
           "Darwin-arm64":"mac_arm_64", "Darwin-x64":"mac_x86_64"}
    decompiler = ghidra/"Ghidra/Features/Decompiler"
    basename = "decompile.exe" if host == "Windows-x64" else "decompile"
    base = decompiler/("build" if host.startswith("Darwin") else "")
    native = base/"os"/ids[host]/basename
    require(native.is_file(), "Expected native decompiler is missing")
    if host.startswith("Darwin"):
        identity = run(["/usr/bin/file", "-b", native], env, output/"native-format.log")
        require_mach_executable(identity, host)
    state = {"platform":host, "ghidra_sha256":pins["ghidra"][3], "jdk_sha256":pins["jdk"][host][1],
             "extensions":expected, "native_sha256":digest(native),
             "runner_image":os.environ.get("ImageVersion"), "os":platform.release()}
    if source is not None:
        if not host.startswith("Darwin"):
            diagnostic.begin("candidate_gradle_pin")
            pin_gradle(gradle)
        extensions = build_candidate(output, source, host, ghidra, env, diagnostic)
        state["source_commit"] = candidate_commit
    (output/"setup.json").write_text(json.dumps(state, indent=2) + "\n")
    return extensions


def expected_files(output, *, candidate=False):
    files = {}
    archive_pins = candidate_archive_pins() if candidate else {name: sha for _, _, name, sha in pins["extensions"]}
    for name, sha in archive_pins.items():
        archive = output / "downloads" / name
        require(digest(archive) == sha, "Extension archive changed")
        with zipfile.ZipFile(archive) as z:
            for entry in z.infolist():
                if not entry.is_dir():
                    files[Path(entry.filename)] = hashlib.sha256(z.read(entry)).hexdigest()
    return files


def extension_tree(output):
    return output/"home/settings/ghidra/ghidra_12.1.3_PUBLIC/Extensions"


def verify_install(output, *, candidate=False):
    prefix = extension_tree(output)
    expected = expected_files(output, candidate=candidate)
    got = {path.relative_to(prefix):digest(path) for path in prefix.rglob("*") if path.is_file()}
    require(got == expected and len(got) == (60 if candidate else 44),
            "Installed extension files differ from the approved ZIPs")
    return len(got)


def headless(output, host, extensions, wrapper, diagnostic, *, candidate=False):
    diagnostic.begin("install_extensions")
    ghidra, java, home, env = paths(output, host)
    for archive in extensions:
        unzip(archive, extension_tree(output))
    installed = verify_install(output, candidate=candidate)
    launcher = wrapper or ghidra/"support"/("analyzeHeadless.bat" if host == "Windows-x64" else "analyzeHeadless")
    projects = output/"projects"
    projects.mkdir()
    reports = {}
    for sample, mode in (("bank-fe","observed"), ("bank-ff","observed"),
                         ("bank-unknown","observed"), ("bank-unknown","static")):
        name = f"{sample}-{mode}"
        original = output/"roms"/f"{sample}.ws"
        receipt = output/f"{name}.txt"
        common = [launcher, projects, name, "-max-cpu", "1", "-scriptPath", output/"example"]
        diagnostic.begin("fixture_import", name)
        imported = run([*common, "-import", original, "-preScript", "ConfigureBankEvidence.java",
                        output/f"{name}.jsonl", mode], env, output/f"{name}-import.log")
        require("Analysis succeeded" in imported and "Save succeeded" in imported, f"Import failed: {name}")
        saved = list((projects/f"{name}.rep").rglob("db.*.gbf"))
        require(len(saved) == 1, f"Expected one saved program database for {name}")
        before = digest(saved[0])
        diagnostic.begin("fixture_reopen", name)
        run([*common, "-process", original.name, "-noanalysis", "-readOnly", "-postScript",
             "VerifyBankedCall.java", original, receipt, mode], env, output/f"{name}-reopen.log")
        text = receipt.read_text()
        overrides = 1 if mode == "observed" else 0
        require(f"sha256\t{pins['fixtures'][original.name]}\n" in text
                and f"physical-overrides\t{overrides}\n" in text
                and "\t9a69000020\n" in text and digest(saved[0]) == before, f"Invalid reopen: {name}")
        if mode == "observed":
            marker, address = ("99","10069") if sample == "bank-ff" else ("42","69")
            require(f"rom-offset\t0x{address}\n" in text and
                    f"uRam00000200=0x{marker};" in "".join(text.split()), f"Wrong expected native output: {name}")
        reports[name] = {"saved_database_sha256":before, "receipt_sha256":digest(receipt), "overrides":overrides}
    result = {"mode":"headless", "platform":host, "installed_files":installed, "projects":reports}
    (output/"headless.json").write_text(json.dumps(result, indent=2) + "\n")
    state = json.loads((output/"setup.json").read_text())
    for key in ("ghidra_sha256", "jdk_sha256", "native_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", state[key]), f"Invalid {key}")
        result[key] = state[key]
    if candidate:
        result["source_commit"] = candidate_commit
    result["extension_sha256"] = list(state["extensions"].values())
    tag = "PUBLIC_GHIDRA_CANDIDATE_HEADLESS_PASS" if candidate else "PUBLIC_GHIDRA_HEADLESS_PASS"
    print(tag + " " + json.dumps(result, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("headless","stage-gui","gui-probe","launch-gui","verify-gui-install"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--candidate-checkout", type=Path)
    parser.add_argument("--local-wrapper", type=Path)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--expected-host", choices=platforms.values())
    args = parser.parse_args()
    output = args.directory.resolve()
    host = platforms.get((platform.system(), platform.machine()))
    diagnostic = Diagnostic(host or "unsupported")
    try:
        require(host is not None and (args.expected_host is None or host == args.expected_host), "Unexpected native host")
        candidate = args.candidate_checkout is not None
        require(not candidate or args.mode in ("headless", "stage-gui"), "Unexpected candidate mode")
        if args.mode in ("headless","stage-gui"):
            extensions = prepare(output, host, args.cache, diagnostic, candidate_checkout=args.candidate_checkout)
            if args.mode == "headless":
                headless(output, host, extensions, args.local_wrapper, diagnostic, candidate=candidate)
        elif args.mode == "verify-gui-install":
            diagnostic.begin("gui_install_verification")
            print(f"{verify_install(output)} installed files match the approved ZIPs")
        else:
            diagnostic.begin("desktop_probe" if args.mode == "gui-probe" else "foreground_gui")
            ghidra, java, home, env = paths(output, host)
            if args.mode == "gui-probe":
                run([java, here/"DesktopProbe.java"], env, output/"desktop.log", timeout=30)
                require("DESKTOP_PROBE_PASS" in (output/"desktop.log").read_text(), "Desktop probe lacked positive evidence")
                print("PUBLIC_GHIDRA_DESKTOP_CAPABLE " + host)
            else:
                launcher = ghidra/"support"/("launch.bat" if host == "Windows-x64" else "launch.sh")
                command = [launcher, "fg", "jdk", "Ghidra", "2G", "", "ghidra.GhidraRun"]
                if args.project:
                    project = args.project.resolve()
                    require(project.is_relative_to(output) and project.suffix == ".gpr", "Expected isolated .gpr")
                    command.append(project)
                index = len(list(output.glob("gui-launch-*.log")))
                run(command, env, output/f"gui-launch-{index}.log", timeout=7200)
    except Exception as error:
        diagnostic.fail(error)
        raise


if __name__ == "__main__":
    main()
