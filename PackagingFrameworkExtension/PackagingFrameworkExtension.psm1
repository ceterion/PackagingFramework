
# Example variabe that will be exported form the module (must be "Global:")
[String]$Global:ExampleVarFromExtension = "Hello World"

#region Function Show-ExampleFunctionFromExtension
Function Show-ExampleFunctionFromExtension {
<#
.SYNOPSIS
	Example Function that simply outputs a textstring that is given as input parameter
.DESCRIPTION
	Not much to say
.PARAMETER String
	A text string
.EXAMPLE
	ExampleFunctionFromExtension -String "Hello World"
.NOTES
	Created by ceterion AG
	This is an internal script function and should typically not be called directly.
.LINK
	http://www.ceterion.com
#>
	[CmdletBinding()]
	Param (
		#  Get the current date
		[Parameter(Mandatory=$True)]
		[ValidateNotNullorEmpty()]
		[string]$String
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Host $String
		}
		Catch {
                Write-Log -Message "Unexpected error . `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
    			If (-not $ContinueOnError) {
				Throw "Unexpected error.: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion Function Show-ExampleFunctionFromExtension

#region PackageStartExtension
[Scriptblock]$Global:PackageStartExtension = {
    
    # The content of this script block will be executed automatically at package start. You can place your own custom code inside this script block

}
#endregion PackageStartExtension

#region PackageEndExtension
[Scriptblock]$Global:PackageEndExtension = {

    # The content of this script block will be executed automatically at package end. You can place your own custom code inside this script block

}
#endregion PackageEndExtension


## Export functions, aliases and variables
Export-ModuleMember -Function * -Alias * -Variable *