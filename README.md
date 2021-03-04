# TracerWithTaintingCapabilities

**Last update: (Mar 3, 2021):** 

**TracerWithTaintingCapabilities** is an open-source dynamic analysis framework for handling evasive malware. 
It handles low-level instructions (int 2d, rdtsc, ...) and evasive APIs used by modern malware.
This tool also perform a fine-grained taint analysis process using libdft where it mark as tainted a number of sources identified in the API hooking.

### Requirements

TracerWithTaintingCapabilities builds on [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) (v3.15 is highly recommended) and requires Visual Studio 2015 or higher for its compilation.

Pin has some dependencies that require manual inclusion in the project. We created a `Locals.props` file that simplifies the project configuration. Its defaults are Pin being installed in `C:\Pin315` and the SDK 8.1 headers being in use: 

```
  <PropertyGroup Label="UserMacros">
    <PinFolder>C:\Pin315</PinFolder>
    <WinHPath>C:/Program Files (x86)/Windows Kits/8.1/Include/um</WinHPath>
  </PropertyGroup>
```

For instance, if you wish to use the SDK 10.0.17763.0 headers, after modifying the Project settings in Visual Studio
you should also change the value of the `WinHPath` property to `C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um`. Similary, modify the property value if your SDK 8.1 headers are installed in `C:/Program Files/` instead of `C:/Program Files (x86)/`. The purpose of this field is to assist Pin when it includes the absolute path of `Windows.h` from its CRT headers.

You should now be able to compile TracerWithTaintingCapabilities. Once compilation ends, you will find a `simpleProfilerAPI32.dll` library in the Pin directory.

### Quick start

To run an executable under TracerWithTaintingCapabilities use:

```
C:\Pin315\pin.exe -t simpleProfilerAPI32.dll [options] -- <file.exe>
```

TracerWithTaintingCapabilities supports the following command-line options:

Option | Meaning
--- | --- 
`-o` | Specify output file to be used for API tracing (default: profile.tag

For instance, to run an evasive program named `sample.exe` in a sandbox-like automatic mode try:

```
C:\Pin315\pin.exe -t simpleProfilerAPI32.dll -- sample.exe
```

TracerWithTaintingCapabilities will create a file named `profile.tag` under Pin's folder `C:\Pin315` that logs all the traced APIs.

### Authors
* Andrea Naspi ([@andreanaspi](https://github.com/AndreaNaspi)) - main developer
