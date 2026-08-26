# D3D12CacheListener

This is a command line ETW listener (similar to [PresentMon](https://github.com/GameTechDev/PresentMon)) that listens to D3D ETW events to measure efficacy of
[advanced shader delivery](https://devblogs.microsoft.com/directx/introducing-advanced-shader-delivery/) PSDBs.

To use, simply run as administrator, or as a user in the Performance Log Users group. Hit rates for D3D12 apps will be printed to console.

## Usage

```
D3D12CacheListener.exe [-v|--verbose] [-h|--help]
```

- `-v`, `--verbose` — dump the full `ASDInit` payload for every `ASDInit` event, not just when the identity check fails.
- `-h`, `--help` — show help text.

## Diagnosing identity failures

When an `ASDInit` event reports `Step: IdentityCheck`, the PSDB was rejected because the
application identity recorded in the database did not match the running application or the
installed compiler. The tool decodes the event payload and presents it as the three comparisons the
identity check actually reasons about, marking each failure inline:

```
  --- ASDInit diagnostics (schemaVersion 3) ---

  Application match      D3D sees now              PSDB was built for
    Name               : "Foo"                     "foo"                     <-- mismatch (differs only by case)
    Engine             : "Bar"                     "Baz"                     <-- mismatch
    Version            : 1.0.0.0                   1.0.0.0
    Engine version     : 2.0.0.0                   2.0.0.0
    Executable         : "foo.exe"                 "foo.exe"

  ABI compatibility      driver                    PSDB compiler
    Adapter family     : "NVIDIA_Turing"           "NVIDIA_Ampere"           <-- mismatch
    Compiler version   : 1.2.3.4                   1.2.0.0
    ABI version        : [3.0.0.0, 5.0.0.0]        7.0.0.0                   <-- out of range

  Application profile
    Driver expects     : 2.1.0.0
    PSDB resolved      : 3.0.0.0                   <-- major version mismatch

  Sources
    Application desc   : SetApplicationIdentity (2)
    Default PSDB       : ShaderCacheRegistration (3)
```

- **Application match** compares what D3D understands the running application to be (from API calls
  or registry information) against what was passed to the compiler when the PSDB was built.
- **ABI compatibility** compares what the driver in the current process reports it supports against
  the compiler that produced the PSDB.
- **Application profile** compares the profile version the driver expects against the profile the
  compiler resolved — that is, whether the compiler recognized the application description and
  applied a profile at all.
- **Sources** records where the application description and the default PSDB path came from. These
  are only present at schema version 3 and later.

Version fields are four packed 16-bit components and are printed in `a.b.c.d` notation. The
application profile version is compared on its leading two components only. If none of the checks
fires, the tool says so explicitly — that means the runtime enforced a check this tool does not yet
model.
