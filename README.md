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

When an `ASDInit` event reports `Step: IdentityCheck`, the PSDB was rejected because the application
identity recorded in the database did not match the running application or the installed compiler.
The tool decodes the full event payload (`AbiSupport`, `ApplicationDesc`, `CompilerIdentity`,
`ApplicationIdentity`, and — for schema version 3 and later — `ApplicationDescSource` and
`DefaultPsdbSource`) and then reports which of the following checks failed:

- Application name mismatch between `ApplicationDesc` and `ApplicationIdentity`
- Engine name mismatch between `ApplicationDesc` and `ApplicationIdentity`
- `CompilerIdentity.ABIVersion` outside the range advertised by `AbiSupport`
- Adapter family mismatch between `AbiSupport` and `CompilerIdentity`
- Application profile version major mismatch (the leading two components) between `AbiSupport` and
  `ApplicationIdentity`

Version fields are four packed 16-bit components and are printed in `a.b.c.d` notation. If none of
the checks above fires, the tool says so explicitly — that means the runtime enforced a check this
tool does not yet model.
