﻿// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portionas of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


namespace Microsoft.Management.Powershell.PFXImport.Cmdlets
{
    using Microsoft.Intune.EncryptionUtilities;
    using System.Management.Automation;

    [Cmdlet(VerbsData.Export, "IntunePublicKey")]
    public class ExportPublicKey: PSCmdlet
    {

        [Parameter(Position = 1, Mandatory = true)]
        public string ProviderName { get; set; }

        [Parameter(Position = 2, Mandatory = true)]
        public string KeyName { get; set; }

        [Parameter(Position = 3, Mandatory = true)]
        public string FilePath { get; set; }

        [Parameter(Position = 4, Mandatory = false)]
        public ManagedRSAEncryption.FileFormat FileFormat { get; set; } = ManagedRSAEncryption.FileFormat.CngBlob;


        protected override void ProcessRecord()
        {
            ManagedRSAEncryption managedRSA = new ManagedRSAEncryption();
            managedRSA.ExportPublicKeytoFile(ProviderName, KeyName, FilePath, FileFormat);
        }
    }
}
