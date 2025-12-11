$null = Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 256,256
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'HighQuality'
$g.Clear([System.Drawing.Color]::FromArgb(15,22,41))

$fillBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(106,230,255))
$g.FillRectangle($fillBrush, 28, 28, 200, 200)

$font = New-Object System.Drawing.Font 'Segoe UI Semibold', 110
$textBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(15,22,41))
$g.DrawString('DG', $font, $textBrush, 36, 54)

$g.Dispose()

$hicon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hicon)
$fs = New-Object System.IO.FileStream ('icon.ico', [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()
[System.Runtime.InteropServices.Marshal]::Release($hicon) | Out-Null
