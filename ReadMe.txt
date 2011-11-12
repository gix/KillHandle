KillHandle
----------

Synopsis

    KillHandle <file-path> [<process-name>]

Description

    Visual Studio 2010 sometimes keeps file handles to compilation targets
    (especially static libraries) open which prevents further build attempts
    of the affected project.

    KillHandle, when used as a pre-build step, works around that bug by
    killing the (presumably leaked) file handles from the first devenv.exe
    process it finds.

    Related Connect-Entry:
        <http://connect.microsoft.com/VisualStudio/feedback/details/551819/vs2010-locks-static-library-after-debug-session>

Options

    <file-path>
        The file path of handles to kill (e.g. "C:\FooLib\Debug\FooLib.lib").
        KillHandle only runs when this specifies the path to an actual file
        system object (that can be opened by CreateFile).

    <process-name>
        The name of the process to inspect. Defaults to "devenv.exe".

Usage

    Copy KillHandle.exe and KillHandle.props to the location of your choice
    and add the property sheet to the affected projects or manually add
    it as Pre-Build Event.

Bugs

    Please report bugs to <https://github.com/gix/KillHandle/issues>.
