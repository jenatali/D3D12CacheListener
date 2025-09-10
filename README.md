# D3D12CacheListener

This is a command line ETW listener (similar to [PresentMon](https://github.com/GameTechDev/PresentMon)) that listens to D3D ETW events to measure efficacy of
[advanced shader delivery](https://devblogs.microsoft.com/directx/introducing-advanced-shader-delivery/) PSDBs.

To use, simply run as administrator, or as a user in the Performance Log Users group. Hit rates for D3D12 apps will be printed to console.
