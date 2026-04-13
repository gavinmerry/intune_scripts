# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install module if not already installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

Import-Module Microsoft.Graph

# Connect and request required scopes
Connect-MgGraph -Scopes @(
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "Group.Read.All"
)

# Get access token
$AccessToken = (Get-MgContext).AccessToken

# Build headers
$Headers = @{
    Authorization = "Bearer $AccessToken"
    Accept        = "application/json"
}

$OutDirectory = Read-Host "[?] Enter output directory path (default: current directory)"
if ([string]::IsNullOrWhiteSpace($OutDirectory)) {
    $OutDirectory = (Get-Location).Path
}
if (-not (Test-Path $OutDirectory)) {
    New-Item -ItemType Directory -Path $OutDirectory -Force | Out-Null
}

Function Get-IntuneAppPermissions {

    Param (
        [Parameter(Mandatory = $True)][hashtable]$Headers,
        [Parameter(Mandatory = $True)][string]$OutDirectory
    )

    $URL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

    $Response = (Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get).Value
    
    $Response | Export-CSV -Path "$OutDirectory\mobileApps.csv" -NoTypeInformation

    #$application = $Response.value | Where-Object { $_.id -eq "2d0cab59-a723-4eb0-8b81-3ce6c70b352e" } # Wireshark with Assignments
    #$application = $Response.value | Where-Object { $_.id -eq "c661b1e7-c2f9-4011-ab63-d75dd08863e7" } # HP Diag with no Assignments

    # CSV Headers
    $CSVHeader = "ApplicationDisplayName,ApplicationID,ApplicationDescription,Intent,Source,AssignedGroup,AssignedGroupID,AssignedGroupDescription,AssignedGroupType,AssignedGroupRule,AssignedGroupMembers"
    Add-Content -Path "$OutDirectory\applicationAssignments.csv" -Value $CSVHeader

    foreach ($application in $Response) {

        $assignmentURL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{$($application.id)}/assignments"
        $assignmentResponse = (Invoke-RestMethod -Uri $assignmentURL -Headers $Headers -Method Get).Value

        If ($application.isAssigned -eq $True) {

            foreach ($assignment in $assignmentResponse) {

                foreach ($target in $assignment.target) {

                    if ($target.groupId) {
        
                        $groupURL = "https://graph.microsoft.com/beta/groups/{$($target.groupId)}"
                        $groupResponse = Invoke-RestMethod -Uri $groupURL -Headers $Headers -Method Get

                        $groupMembersURL = "$groupURL/members"
                        $groupMembersResponse = Invoke-RestMethod -Uri $groupMembersURL -Headers $Headers -Method Get
            
                        # Prepare the CSV data string
                        $AssignmentData = @(
                            (Quote-CsvField $application.displayName),
                            (Quote-CsvField $application.id),
                            (Quote-CsvField $application.description),
                            (Quote-CsvField $assignment.intent),
                            (Quote-CsvField $assignment.source),
                            (Quote-CsvField $groupResponse.displayName),
                            (Quote-CsvField $groupResponse.id),
                            (Quote-CsvField $groupResponse.description),
                            (Quote-CsvField ($groupResponse.groupTypes -join ',')),
                            (Quote-CsvField $groupResponse.membershipRule),
                            (Quote-CsvField ($groupMembersResponse.value.Count))
                        ) -join ','

                        # Append the formatted string to the CSV file
                        Add-Content -Path "$OutDirectory\applicationAssignments.csv" -Value $AssignmentData
                    }
                }
            }
        }
    }
}

Function Get-IntuneManagementScripts {

    Param (
        [Parameter(Mandatory = $True)][hashtable]$Headers,
        [Parameter(Mandatory = $True)][string]$OutDirectory
    )

    $URL = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"

    $Response = (Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get).Value
    
    $ScriptHeaders = $scriptResponse.PSObject.Properties.Name -join ','
    Add-Content -Path "$OutDirectory\deviceManagementScriptContent.csv" -Value $ScriptHeaders

    #$script = $Response.value[0]

    foreach ($script in $Response) {

        $scriptURL = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{$($script.id)}"
        $scriptResponse = Invoke-RestMethod -Uri $scriptURL -Headers $Headers -Method Get

        $ScriptFields = @()

        foreach ($propertyName in $scriptResponse.PSObject.Properties.Name) {
            if ($propertyName -eq 'scriptContent') {
                # Handle scriptContent specially
                $decodedScriptContent = ConvertFrom-Base64 -String $scriptResponse.scriptContent
                $ScriptFields += Quote-CsvField $decodedScriptContent
            } else {
                # For all other properties, just quote the CSV field
                $ScriptFields+= Quote-CsvField $scriptResponse.$propertyName
            }
        }

        $ScriptData = $ScriptFields -join ','

        # Append the formatted string to the CSV file
        Add-Content -Path "$OutDirectory\deviceManagementScriptContent.csv" -Value $ScriptData
    }
}

Function Get-IntuneDeviceConfigurationScripts {

    Param (
        [Parameter(Mandatory = $True)][hashtable]$Headers,
        [Parameter(Mandatory = $True)][string]$OutDirectory
    )

    If (-not (Test-Path -Path "$OutDirectory\deviceConfigurations")) {
        New-Item -Path "$OutDirectory\deviceConfigurations" -ItemType Directory
    }


    $URL = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"

    $Response = (Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get).Value

    # Get unique @odata.types
    $uniqueTypes = $Response | Select-Object -ExpandProperty '@odata.type' -Unique

    foreach ($type in $uniqueTypes) {
        # Extract the last element of the type name
        $typeName = $type -split '\.' | Select-Object -Last 1

        # Filter $Response items that match the current type
        $filteredData = $Response | Where-Object { $_.'@odata.type' -eq $type }

        # Define CSV file name
        $csvFileName = "$typeName.csv"

        # Export the filtered data to a CSV file
        $filteredData | Export-Csv -Path "$OutDirectory\deviceConfigurations\$csvFileName" -NoTypeInformation
    }
}

Function Get-IntuneGroupPolicyScripts {

    Param (
        [Parameter(Mandatory = $True)][hashtable]$Headers,
        [Parameter(Mandatory = $True)][string]$OutDirectory
    )

    $URL = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"

    $Response = (Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get).Value

    $Response | Export-CSV -Path "$OutDirectory\groupPolicyScripts.csv" -NoTypeInformation

}

Function Get-IntuneEndpointSecurityScripts {

    Param (
        [Parameter(Mandatory = $True)][hashtable]$Headers,
        [Parameter(Mandatory = $True)][string]$OutDirectory
    )

    If (-not (Test-Path -Path "$OutDirectory\endpointSecurity")) {
        New-Item -Path "$OutDirectory\endpointSecurity" -ItemType Directory
    }

    # All Endpoint Security Script Types
    $URL = "https://graph.microsoft.com/beta/deviceManagement/intents"

    $Response = (Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get).Value

    $Response | Export-CSV -Path "$OutDirectory\endpointSecurity\endpointSecurityScripts.csv" -NoTypeInformation

    foreach ($endpointSecurityScript in $Response) {

        $scriptSettingsURL = "https://graph.microsoft.com/beta/deviceManagement/intents/{$($endpointSecurityScript.id)}/settings"
        $scriptSettingsReponse = (Invoke-RestMethod -Uri $scriptSettingsURL -Headers $Headers -Method Get).Value

        foreach ($setting in $scriptSettingsReponse) {
            Try {
                $setting | Export-CSV -Path "$OutDirectory\endpointSecurity\$($endpointSecurityScript.displayName)_Settings.csv" -Append -NoTypeInformation
            }
            Catch {
                Continue
            }
        }

        $scriptAssignmentsURL = "https://graph.microsoft.com/beta/deviceManagement/intents/{$($endpointSecurityScript.id)}/assignments"
        $scriptAssignmentsReponse = (Invoke-RestMethod -Uri $scriptAssignmentsURL -Headers $Headers -Method Get).Value

        foreach ($assignment in $scriptAssignmentsReponse) {
            Try {
                $assignedGroup = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/{$($assignment.target.groupId)}" -Headers $Headers -Method Get
                $assignedGroup | Export-CSV -Path "$OutDirectory\endpointSecurity\$($endpointSecurityScript.displayName)_Assignments.csv" -Append -NoTypeInformation
            }
            Catch {
                Continue
            }
        }
    }       

    # W10 - D - TRAINING - Bitlocker
    #https://graph.microsoft.com/beta/deviceManagement/intents/{7755f8e0-bf11-4e51-9bda-0600bb479ff9}/settings
    #https://graph.microsoft.com/beta/deviceManagement/intents/{7755f8e0-bf11-4e51-9bda-0600bb479ff9}/assignments
    #    "groupId": "ff544719-770f-40ba-9a30-dc3ddf74db90"
    #    "groupId": "7d2a2705-9fb1-4802-a537-ba8e14f158ed"

    # https://graph.microsoft.com/beta/deviceManagement/intents/{7755f8e0-bf11-4e51-9bda-0600bb479ff9}/categories/{b65b2f09-a697-41e9-add3-1115e09aa393}

}


# ------- HELPER FUNCTIONS -------

# Function to escape and quote a single field for CSV
function Quote-CsvField {
    param (
        [string]$Field
    )

    # Replace all instances of " with ""
    $escapedField = $Field -replace '"', '""'

    # Surround with quotes and return
    return "`"$escapedField`""
}

<#
    Base64 Encoding and Decoding Functions for Constrained Language Mode
    License: GPLv3
    Author: @ChrisTruncer
#>

function ConvertFrom-Base64
{
    param
    (
        [Parameter(Mandatory = $False, ParameterSetName='StringMethod')]
        [String]$String,
        [Parameter(Mandatory = $False, ParameterSetName='FileMethod')]
        [String]$FilePath,
        [Parameter(Mandatory = $False, ParameterSetName='FileMethod')]
        [Parameter(ParameterSetName='StringMethod')]
        [String]$OutPath,
        [Parameter(Mandatory = $False)]
        [HashTable]$AltAlphabet
    )

    Process
    {
        $base64_values = Validate-Alphabet -IncomingHTable $AltAlphabet

        if($String)
        {
            # Initialze decoded string value
            $decodeddata = ''
            $decodeme = $String
        }
        elseif($FilePath)
        {
            $decodeddata = @()
            $decodeme = Get-Content -Path $FilePath
        }

        # Check for how much padding is used
        $padding_value = 0
        if($decodeme.EndsWith($base64_values['Padding'] * 2))
        {
            $padding_value = 2
        }
        elseif($decodeme.EndsWith($base64_values['Padding'] * 1))
        {
            $padding_value = 1
        }

        $decodeme_length = $decodeme.Length
        $encoded_data = @()

        for($og_counter = 0; $og_counter -le ($decodeme_length - 1); $og_counter += 4)
        {
            $encoded_data = "$($decodeme[$og_counter])$($decodeme[$og_counter+1])$($decodeme[$og_counter+2])$($decodeme[$og_counter+3])"
            # set up defaults
            $lastgroup = $false
            $letter_bits = ''
        
            # Detect if in the last group of 4 characters
            if($og_counter -eq $decodeme_length - 4)
            {
                $lastgroup = $true
            }
        
            # Start working on each encoded letter
            foreach($letter in $encoded_data.ToCharArray())
            {
                if ($letter -ne $base64_values.Padding)
                {
                    Foreach ($Key in ($base64_values.GetEnumerator() | Where-Object {$_.Value -ceq $letter}))
                    {
                        $letter_value = $Key.name
                    }
                    $incoming_bits = [Convert]::ToString($letter_value, 2)

                    # Make sure we get 6 bits
                    if($incoming_bits.Length -ne 6)
                    {
                        $missing = 6 - $incoming_bits.Length
                        $incoming_bits = '0' * $missing + $incoming_bits
                    }
                }
                else
                {
                    $incoming_bits = '000000'
                }
                $letter_bits += $incoming_bits
            }

            # Break the 24 bits into groups of eight
            # Store string in an array
            $bit_array = @()
            $decoder_counter = 0
            for($counter_dos = 0; $counter_dos -le ($letter_bits.length-1); $counter_dos += 8)
            {
                $bit_array = "$($letter_bits[$counter_dos])$($letter_bits[$counter_dos+1])$($letter_bits[$counter_dos+2])$($letter_bits[$counter_dos+3])$($letter_bits[$counter_dos+4])$($letter_bits[$counter_dos+5])$($letter_bits[$counter_dos+6])$($letter_bits[$counter_dos+7])"
            
                if($bit_array -ne '00000000')
                {
                    if($String)
                    {
                        [char][byte]$real_letter = ConvertTo-Decimal -BinaryValue $bit_array
                        $decodeddata += $real_letter
                    }
                    elseif($FilePath)
                    {
                        [byte][int]$real_letter = ConvertTo-Decimal -BinaryValue $bit_array
                        $decodeddata += $real_letter
                    }
                }
                else
                {
                    if($lastgroup -eq $false)
                    {
                        $decodeddata += [byte]00
                    }
                    elseif($lastgroup -eq $true)
                    {
                        switch($decoder_counter)
                        {
                            0
                            {
                                $decodeddata += [byte]00
                            }
                            1
                            {
                                switch($padding_value)
                                {
                                    0
                                    {
                                        $decodeddata += [byte]00
                                    }
                                    1
                                    {
                                        $decodeddata += [byte]00
                                    }
                                    2
                                    {
                                        Write-Verbose "There should be an padded value, not appending data"
                                    }
                                }
                            }
                            2
                            {
                                switch($padding_value)
                                {
                                    0
                                    {
                                        $decodeddata += [byte]00
                                    }
                                    1
                                    {
                                        Write-Verbose "This should be the last padded value, not appending data"
                                    }
                                    2
                                    {
                                        Write-Verbose "This should be the last padded value, not appending data"
                                    }
                                }
                            }
                        }
                    }
                }
                $decoder_counter += 1
            }
        } # End of foreach group bracket

        if($OutPath)
        {
            [byte[]]$outdata = $decodeddata
            Set-Content -Encoding byte -Value $outdata -Path $OutPath
        }
        else
        {
            $decodeddata
        }
    } # End of process bracket
}

function ConvertTo-Base64
{
    param
    (
        [Parameter(Mandatory = $False, ParameterSetName='StringMethod')]
        [String]$String,
        [Parameter(Mandatory = $False, ParameterSetName='FileMethod')]
        [String]$FilePath,
        [Parameter(Mandatory = $False, ParameterSetName='FileMethod')]
        [Parameter(ParameterSetName='StringMethod')]
        [String]$OutPath,
        [Parameter(Mandatory = $False)]
        [HashTable]$AltAlphabet
    )

    Process
    {
        # Try to validate hashtable if provided one
        # otherwise defer to default base64 values
        if($AltAlphabet)
        {
            $base64_values = Validate-Alphabet -IncomingHTable $AltAlphabet
        }
        else
        {
            $base64_values = Validate-Alphabet
        }

        # Get data that is encoded based on if it is a string or file
        if($String)
        {
            $datatoencode = $String
        }
        elseif($FilePath)
        {
            $datatoencode = Get-Content -Encoding Byte -Path $FilePath
        }
        else
        {
            Throw 'This should never hit'
        }

        # Initialize encoded string variable
        $encodeddata = ''

        # Find if string is divisible by three
        $remainder = $datatoencode.Length % 3
        $padme = $false
        if($remainder -ne 0)
        {
            $padme = $true
            $remainder = 3 - $remainder
        }

        # Find quotient of length divided by 3
        [int]$quotient = $datatoencode.Length / 3

        # Set counter to trigger every 3 iterations
        $counter = 0

        # Store string bits
        $storebits = ''
        $endequals = $false

        for($datalength = 0; $datalength -lt $datatoencode.Length; $datalength++)
        {
            # Increment counter variable
            $counter++

            # Convert individual letter to binary representation
            # and ensure it is 8 bits long
            $decimalvalue = [byte][char]$datatoencode[$datalength]
            $incomingbits = [Convert]::ToString($decimalvalue, 2)
            # Make sure $incomingbits is 8 bits long
            if($incomingbits.Length -ne 8)
            {
                $missing = 8 - $incomingbits.Length
                $incomingbits = '0' * $missing + $incomingbits
            }
            $storebits += $incomingbits

            if(($datalength -eq $datatoencode.Length-1) -or ($datalength -eq $datatoencode.Length-2))
            {
                $endequals = $true
            }

            if((($remainder -eq 0) -or ($remainder -ne 0)) -and ($counter -eq 3))
            {
                # Add to $storebits and get encoded values
                # Convert six 0s into As
                $countertwo = 0

                # Break the 24 bits into groups of four
                # Store string in an array
                $bitarray = @()
                for($countertwo = 0; $countertwo -le ($storebits.length-1); $countertwo += 6)
                {
                    $bitarray += "$($storebits[$countertwo])$($storebits[$countertwo+1])$($storebits[$countertwo+2])$($storebits[$countertwo+3])$($storebits[$countertwo+4])$($storebits[$countertwo+5])"
                }

                # Loop over array containing 4 "rows" of 6 bits, convert each row
                # to the corresponding value in the base64 alphabet/chart
                for($trydos = 0; $trydos -lt $bitarray.Length; $trydos++)
                {
                    if($bitarray[$trydos] -ne '000000')
                    {
                        $baseten = ConvertTo-Decimal -BinaryValue $bitarray[$trydos]
                        $encodeddata += $base64_values.Get_Item($baseten)
                    }
                    else
                    {
                        $encodeddata += 'A'
                    }
                }
            }

            elseif(($remainder -ne 0) -and ($datalength -eq $datatoencode.Length - 1))
            {
                # Add to $storebits, pad as needed
                # Convert six 0s into equal signs
                $countertwo = 0
                $storebits += '00000000' * $remainder

                # Break the 24 bits into groups of four
                # Store string in an array
                $bitarray = @()
                for($countertwo = 0; $countertwo -le ($storebits.length-1); $countertwo += 6)
                {
                    $bitarray += "$($storebits[$countertwo])$($storebits[$countertwo+1])$($storebits[$countertwo+2])$($storebits[$countertwo+3])$($storebits[$countertwo+4])$($storebits[$countertwo+5])"
                }

                # Loop over array containing 4 "rows" of 6 bits, convert each row
                # to the corresponding value in the base64 alphabet/chart
                $acounter = 0
                foreach($binaryvalue in $bitarray)
                {
                    if($binaryvalue -ne '000000')
                    {
                        $baseten = ConvertTo-Decimal -BinaryValue $binaryvalue
                        $encodeddata += $base64_values.Get_Item($baseten)
                        $acounter += 1
                    }
                    else
                    {
                        $encodeddata += 'A'
                    }
                }
            }

            # Reset variables every three runs
            if($counter -eq 3)
            {
                $storebits = ''
                $counter = 0
            }
        }

        if($padme)
        {
            if(($encodeddata[-2] -ceq $base64_values[0]) -and ($encodeddata[-1] -ceq $base64_values[0]) -and ($remainder -eq 1))
            {
                $encodeddata = $encodeddata.SubString(0,$encodeddata.Length-1)
                $encodeddata += $base64_values["Padding"] * 1
            }
            elseif(($encodeddata[-2] -ceq $base64_values[0]) -and ($encodeddata[-1] -ceq $base64_values[0]) -and ($remainder -eq 2))
            {
                $encodeddata = $encodeddata.SubString(0,$encodeddata.Length-2)
                $encodeddata += $base64_values["Padding"] * 2
            }
            elseif($encodeddata[-1] -ceq $base64_values[0])
            {
                $encodeddata = $encodeddata.SubString(0,$encodeddata.Length-1)
                $encodeddata += $base64_values["Padding"]
            }
        }

        if($OutPath)
        {
            Out-File -InputObject $encodeddata -FilePath $OutPath
        }
        else
        {
            $encodeddata
        }
    } # End of Process
}

# Thanks to @DanielHBohannon for sending this function over
function ConvertTo-Decimal
{
    param
    (
        [Parameter(Mandatory = $True)]
        [String]$BinaryValue
    )

    Process
    {
        $decimal_value=0
        $counter=0
        $powers=@(1,2,4,8,16,32,64,128)
        $BinaryValue[($BinaryValue.Length-1)..0] | ForEach-Object { If ($_ -eq '1') { $decimal_value += $powers[$counter] } $counter++ }
        $decimal_value
    }
}

function Validate-Alphabet
{
    param
    (
        [Parameter(Mandatory = $False)]
        [HashTable]$IncomingHTable
    )

    Process
    {
        $default = @{
            0 = "A"
            1 = "B"
            2 = "C"
            3 = "D"
            4 = "E"
            5 = "F"
            6 = "G"
            7 = "H"
            8 = "I"
            9 = "J"
            10 = "K"
            11 = "L"
            12 = "M"
            13 = "N"
            14 = "O"
            15 = "P"
            16 = "Q"
            17 = "R"
            18 = "S"
            19 = "T"
            20 = "U"
            21 = "V"
            22 = "W"
            23 = "X"
            24 = "Y"
            25 = "Z"
            26 = "a"
            27 = "b"
            28 = "c"
            29 = "d"
            30 = "e"
            31 = "f"
            32 = "g"
            33 = "h"
            34 = "i"
            35 = "j"
            36 = "k"
            37 = "l"
            38 = "m"
            39 = "n"
            40 = "o"
            41 = "p"
            42 = "q"
            43 = "r"
            44 = "s"
            45 = "t"
            46 = "u"
            47 = "v"
            48 = "w"
            49 = "x"
            50 = "y"
            51 = "z"
            52 = "0"
            53 = "1"
            54 = "2"
            55 = "3"
            56 = "4"
            57 = "5"
            58 = "6"
            59 = "7"
            60 = "8"
            61 = "9"
            62 = "+"
            63 = "/"
            "Padding" = "="
        }

        # This is checking to make sure parameter exists, and there are at least
        # 64 values (hence, base64)
        if($IncomingHTable -and ($IncomingHTable.count -eq 65))
        {
            # Validate all values provided are unique
            $htvalues = $IncomingHTable.keys | foreach-object { $IncomingHTable[$_] } | Select-Object -unique
            if($htvalues.count -eq 65)
            {
                $base64_alphabet = $IncomingHTable
                Write-Verbose "Validated supplied charset and using it"
            }
            # If this hits, then the values provided weren't unique
            else
            {
                $base64_alphabet = $default
                Write-Verbose "Provided alphabet did not use unique letters, defaulting to standard base64 charset"
            }
        }
        else
        {
            Write-Verbose "Either no alternate alphabet provided, or alternate alphabet does not contain 65 values"
            Write-Verbose "Using the default base64 alphabet"
            $base64_alphabet = $default
        }
        return $base64_alphabet
    }
}

function Test-EncodingBase64
{
    For ($i=0; $i -le 1000; $i++)
    {
        $ran_length = Get-Random -Minimum 1 -Maximum 50
        $clearstring = -join ((65..90) + (97..122) | Get-Random -Count $ran_length | ForEach-Object {[char]$_})

        $encoded = ConvertTo-Base64 -String $clearstring

        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($clearstring)
        $EncodedText =[Convert]::ToBase64String($Bytes)

        # Check encoding from this script and normal way to encode
        if($encoded -ne $EncodedText)
        {
            Write-Output "Encoded data $encoded does not equal $EncodedText from string $clearstring"
        }

        $decoded = ConvertFrom-Base64 -String $encoded
        $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedText))

        # Check encoding from this script and normal way to encode
        if($decoded -ne $DecodedText)
        {
            Write-Output "Decoded Data $decoded does not equal $DecodedText"
        }

        if($decoded -ne $clearstring)
        {
            Write-Output "Cleartext Data $Clearstring does not equal $decoded"
        }
    }
}


Get-IntuneDeviceConfigurationScripts -Headers $Headers -OutDirectory $OutDirectory
