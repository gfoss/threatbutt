#requires -version 3.0

  #======================================#
  # ThreatButt Virtual Attribution Dice  #
  # greg . foss [at] owasp . org         #
  # v0.1  --  May 2015                   #
  #======================================#

#=======================================================================================
# ThreatButt Attribution - 100% Accuracy Guaranteed, Every Time
#=======================================================================================

function butt {

# Hide errors, because I can't PowerShell
$ErrorActionPreference = 'silentlycontinue'

# Acurately determine the Attacker's IP address using next-gen attribution techniques developed by the NSA
function attribution {
    return [IPAddress]::Parse([String] (Get-Random) ).IPAddressToString
}
$buttIP = Write-Output (attribution)

# Talk to the ThreatButt
$buttHash = Get-Random -input "03bf4710574fcfc04aebeaa802a34d29", "f121eb65604a8e2490318de5dd454e83"
$buttActor = Invoke-RestMethod -Method POST -Uri "http://threatbutt.io/api" -Body $buttIP
$buttMalware = Invoke-RestMethod -Method POST -Uri "http://api.threatbutt.io/api/md5/$buttHash"
if ( $buttActor -eq "Please try again later" ) {
    $buttActor = "Chris Roberts"
} if ( $buttActor -eq "Concentrate and ask again" ) {
    $buttActor = "Squirrel"
} else {
}

# Integrate Premium Threat Data Feeds
$buttLocation = Get-Random -input "office", "kitchen", "dining room", "school", "park", "theater", "datacenter", "basement", "attic", "bathroom", "parking lot", "apple store", "apartment", "house", "airplane", "ISS Space Station"
$buttDevice = Get-Random -input "mom's laptop", "dad's laptop", "super computer", "speak and spell", "ti 83", "i Pad", "i Phone", "i watch", "tablet", "easy bake oven", "airplane attacker 3000", "Mars Rover"
$phrase = "Attack detected from $buttActor. In the $buttLocation. With the $buttMalware. Using their $buttDevice..."

# Tell the entire SOC all about the Attack
[Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null 
$object = New-Object System.Speech.Synthesis.SpeechSynthesizer 
$object.SelectVoiceByHints('Female')
$object.Speak($phrase)

# Log the Attack and Attribution Data
New-EventLog -LogName Application -Source "The ThreatButt"
Write-EventLog -LogName Application -Source "The ThreatButt" -EntryType Information -EventId 1337 -Message "$phrase"

# Tell us who did it!
echo ""
$phrase
}

butt

<#
                        ▄▄▄▓▓▓▓▓▓▌▄                                                 
                     ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓µ                                              
                   ╓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌                                             
                  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                            
                 ▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▄▀▓▓▓▓▌                                           
                ▓▓▓▓▓▓▓▓▓▓▓█▌▓▓▓▓▓Γ▀▓▓▓▓▓                        ,▄▌▌▄▄             
               ▄▓▓▓▓▓Γ▓▓▓▓▓╓▓▓▓▓▓█  ▓▌▓▓▓▓                      ╫▓.   Γ▀▀██▓▄▄      
             ╒▓▓▓▓▓ ▀▓╣▓▓▓▓▓▓▓▓▓█ ,▄▓▄▓▓▓▓                     ╓▓^ ╒▄ ,      ▀▓▄    
             ▓▓▓▓▓█ ╓▓▓▓▓▓▓▄▀█▓▄▓▓▓▓▓▓▓▓▓▓▓                    ▓▌  ▄µ,▀ ▀⌐╓▄  ▓▀    
             █▓▓▓▄▓█▓▓▓▓▓▓▓▓▓▓▓█▓▓▓██▀╠▓▓▓▓µ                  ▄▓  ▄▄ Γ`╜▀ ▓Γ ╬▓     
              ╟▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▀▀,▄▓▓▓▓▓██▓                 ╒▓  ╒▄ ƒ▀ █ ▓▌ ╓▓      
              ▐▓▓▓▓██▓▓▓▓▓█▀Γ,▄▄▓▓▓██▀Γ    ▓▓                ▓▀  ▄µ,▀ ▀⌐▐▓  ▓▀      
               ▓▄▄▓██▀▀▄▄▄▓▓▓▓██▀.          ▓▓           ▄▄▄▓▓  ╔▄ ▀ Å▀ ▓Γ ▓▓       
               ▓▓▓▓▓▓▓▓▓▓▀▀Γ        ▄╦ █▌    ▓▓     ▄▓█▀▀ΓΓ▀▓─ ╒▄ ╙▀ⁿ█ ▓▌ ╓▓        
               └▓▓▀▀Γ                ▓  ▓▄    ▓▓ ╓▓█Γ,    ,▓▓▄▄▄▄▄▓,█⌐▐▓  ▓Γ        
                █▓                    ▓ ▐▓     ▓▓▓   ▀█▓▓▓▀ΓΓ     Γ▀▀▓▓Γ ▓█         
                "▓µ                   █▄ █▓     ▓▌  ▀,▓▀              ▀▓▄▓          
                 ▓▓                    ▓  ▓µ     Γ   ▓Γ     ╕          █▓▀          
                  ▓▌                   ▐▓ ▐▓               █            ▓           
                   ▓▓                   █▌ ▓▓▄▄,                       ▓▓           
                    █▓µ                 ╓▓  ▄▄,▐▓▓        ,▄          ▐▓            
                     ╙▓▄                ▓Γ▓▄▀▓▀▀▀           ╓▒       ▄▓             
                       ▓▓╕              ▓▄▓█▓▓                 Φ   ,▓▓              
                        Γ▓▓              Γ                       ▄▓▓▀               
                          ╙▓▌,                             ▄▄▄▓▓█▀Γ                 
                            ▀█▓▄,                     ╓▄▓▌ ╙▓▄                      
                               Γ▀▓▓▌▄▄,       ,,▄▄▄▓▓█▀Γ└▓  ▓▓                      
                                   ΓΓ▀▀▀▓▓▀▓▓▀▀▀▀▀Γ ,,,  ▓▓ ╙▓                      
                                        █▌ ▓▌      ▀▓▓▀▀▀█▓M █▓                     
                                        ▓▌ ▓▌        ▀▓▓▄,    ▓                     
                                 ,▄▄▄,  ▓▌ ▓▌           Γ▀██▓▓▓Γ                    
                                 █▓▄Γ▀█▓▓▌]▓                                        
                                  ╙█▓▄  Γ ▐▓                                        
                                     Γ██▓▓▓▀                                        
        Sweet ASCII Art Stolen from: https://github.com/asshurtmacfags/threatbutt
#>