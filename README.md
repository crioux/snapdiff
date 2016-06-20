# snapdiff
Windows Installation Diff Tool

SnapDiff captures filesystem and registry changes performed by Windows installers.

You run SnapDiff, specifying what subdirectories and registry keys to 'snapshot', and it recursively captures the list of files and keys and values at those locations.
Then it waits while you perform an installation of a piece of software. 
After the installer is complete, you return to SnapDiff and it creates a second snapshot. 

Finally, it creates a zip file of the files and registry keys that were added/changed between the two snapshots. 

This is useful for moving Windows programs to Wine under Linux, where the application may run fine, but the ability to run the installer is limited.

