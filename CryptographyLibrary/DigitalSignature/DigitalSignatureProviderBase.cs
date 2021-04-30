using System;
using System.Collections.Generic;
using CryptographyLibrary.AsymmetricEncryption;
using CryptographyLibrary.Enums;
using CryptographyLibrary.Interfaces;

namespace CryptographyLibrary.DigitalSignature
{
    public abstract class DigitalSignatureProviderBase: IDigitalSignatureProvider
    {
        protected DigitalSignatureProviderOptions Options;

        protected DigitalSignatureProviderBase(DigitalSignatureProviderOptions options)
        {
            Options = options;
        }
        
        protected abstract void AssignNewKey();
        
        public abstract byte[] Sign(byte[] toSign);

        public abstract bool Verify(byte[] signature, byte[] toCompare);
    }
}