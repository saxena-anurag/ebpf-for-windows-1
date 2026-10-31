# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force

function Write-NamespaceSeed {
    param(
        [string] $Name,
        [byte] $Namespace,
        [UInt16] $ReplyLength,
        [UInt32] $Operation,
        [byte[]] $Body
    )

    $length = [UInt16](8 + $Body.Length)
    $message = [byte[]](
        @(0x4e, 0x53, $Namespace) +
        [BitConverter]::GetBytes($ReplyLength) +
        [BitConverter]::GetBytes($length) +
        @(0, 0) +
        [BitConverter]::GetBytes($Operation) +
        $Body)
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory $Name), $message)
}

$namespaceA = [Guid]'11111111-2222-3333-0102-030405060708'
$namespaceB = [Guid]'eeeeeeee-dddd-cccc-0807-060504030201'
$path = [Text.Encoding]::UTF8.GetBytes('/fuzz/namespace/shared')
$invalidHandle = [BitConverter]::GetBytes([Int64]-1)

Write-NamespaceSeed -Name 'namespace-set-a' -Namespace 0 -ReplyLength 0 -Operation 46 -Body $namespaceA.ToByteArray()
Write-NamespaceSeed -Name 'namespace-set-b' -Namespace 1 -ReplyLength 0 -Operation 46 -Body $namespaceB.ToByteArray()
foreach ($namespace in 0..2) {
    Write-NamespaceSeed -Name "namespace-get-$namespace" -Namespace $namespace -ReplyLength 24 -Operation 47 -Body @()
    Write-NamespaceSeed -Name "namespace-pin-open-$namespace" -Namespace $namespace -ReplyLength 16 -Operation 12 -Body $path
    Write-NamespaceSeed -Name "namespace-pin-delete-$namespace" -Namespace $namespace -ReplyLength 0 -Operation 11 -Body ([byte[]]($invalidHandle + $path))
    Write-NamespaceSeed -Name "namespace-map-enumerate-$namespace" -Namespace $namespace -ReplyLength 12 -Operation 23 -Body ([BitConverter]::GetBytes([UInt32]0))
    Write-NamespaceSeed -Name "namespace-pin-enumerate-$namespace" -Namespace $namespace -ReplyLength 128 -Operation 38 -Body ([BitConverter]::GetBytes([UInt32]0))
}
Write-NamespaceSeed -Name 'namespace-native-ex-missing-module' -Namespace 1 -ReplyLength 40 -Operation 49 -Body $namespaceA.ToByteArray()
