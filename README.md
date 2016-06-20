# snapdiff
Windows Installation Diff Tool

SnapDiff captures filesystem and registry changes performed by Windows installers.

You run SnapDiff, specifying what subdirectories and registry keys to 'snapshot', and it recursively captures the list of files and keys and values at those locations.
Then it waits while you perform an installation of a piece of software. 
After the installer is complete, you return to SnapDiff and it creates a second snapshot. 

Finally, it creates a zip file of the files and registry keys that were added/changed between the two snapshots. 

This is useful for moving Windows programs to Wine under Linux, where the application may run fine, but the ability to run the installer is limited.

---

Note that this tool is not written in the most 'optimal' fashion, which would involve process-level monitoring of the installer. This functionality may be offered eventually, but for now, you can expect that files and registry keys modified or changed by other processes than the installer may pollute the output zip file. These still need to be cleaned up by hand. This is a known limitation at this time and may be resolved in future releases.
