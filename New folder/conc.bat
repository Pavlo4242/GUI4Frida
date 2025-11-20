@echo off
set "source_dir=D:\ANDROID\FridaGUI\New folder"  REM Replace with your directory path
set "output_file=101.txt"  REM Replace with desired output name

if not exist "%source_dir%" (
    echo Source directory does not exist!
    exit /b 1
)

echo. > "%output_file%"
for /r "%source_dir%" %%f in (*.ps1) do (
    echo --- File: %%f --- >> "%output_file%"
    type "%%f" >> "%output_file%"
    echo. >> "%output_file%"
)

echo Done!
pause