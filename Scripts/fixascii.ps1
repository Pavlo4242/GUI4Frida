Get-ChildItem -Recurse -Filter "*.js" | ForEach-Object {
    $filePath = $_.FullName
    Write-Host "Cleaning: $filePath"
    
    try {
        # Read as bytes to handle any encoding
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        
        # Convert to UTF-8 without BOM
        $encoding = [System.Text.Encoding]::UTF8
        $content = $encoding.GetString($bytes)
        
        # Remove BOM if present
        if ($content.StartsWith([char]0xFEFF)) {
            $content = $content.Substring(1)
        }
        
        # Remove all non-ASCII characters except basic punctuation
        $cleanContent = ""
        foreach ($char in $content.ToCharArray()) {
            if ([int]$char -le 127 -or $char -eq "`n" -or $char -eq "`r" -or $char -eq "`t") {
                $cleanContent += $char
            } else {
                # Replace problematic chars with safe equivalents
                switch ([int]$char) {
                    0x2192 { $cleanContent += "->" }  # →
                    0x2190 { $cleanContent += "<-" }  # ←  
                    0x26A0 { $cleanContent += "!!" }  # ⚠
                    0x2013 { $cleanContent += "-" }   # –
                    0x2014 { $cleanContent += "-" }   # —
                    0x201C { $cleanContent += '"' }   # “
                    0x201D { $cleanContent += '"' }   # ”
                    0x2018 { $cleanContent += "'" }   # ‘
                    0x2019 { $cleanContent += "'" }   # ’
                    default { 
                        Write-Host "  Replaced char: U+$([convert]::ToString([int]$char, 16))" -ForegroundColor Yellow
                        $cleanContent += "?" 
                    }
                }
            }
        }
        
        # Save with UTF-8 without BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($filePath, $cleanContent, $utf8NoBom)
        
        Write-Host "  Cleaned: $filePath" -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed: $filePath" -ForegroundColor Red
    }
}

Write-Host "All files cleaned and converted to ASCII-safe UTF-8" -ForegroundColor Green