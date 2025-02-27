﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;

namespace System.Reflection.Emit
{
    internal sealed class MethodBuilderImpl : MethodBuilder
    {
        private readonly Type _returnType;
        private readonly Type[]? _parameterTypes;
        private readonly ModuleBuilderImpl _module;
        private readonly string _name;
        private readonly CallingConventions _callingConventions;
        private readonly TypeBuilderImpl _declaringType;
        private MethodAttributes _attributes;
        private MethodImplAttributes _methodImplFlags;

        internal DllImportData? _dllImportData;
        internal List<CustomAttributeWrapper>? _customAttributes;

        internal MethodBuilderImpl(string name, MethodAttributes attributes, CallingConventions callingConventions, Type? returnType,
            Type[]? parameterTypes, ModuleBuilderImpl module, TypeBuilderImpl declaringType)
        {
            _module = module;
            _returnType = returnType ?? _module.GetTypeFromCoreAssembly(CoreTypeId.Void);
            _name = name;
            _attributes = attributes;
            _callingConventions = callingConventions;
            _declaringType = declaringType;

            if (parameterTypes != null)
            {
                _parameterTypes = new Type[parameterTypes.Length];
                for (int i = 0; i < parameterTypes.Length; i++)
                {
                    ArgumentNullException.ThrowIfNull(_parameterTypes[i] = parameterTypes[i], nameof(parameterTypes));
                }
            }

            _methodImplFlags = MethodImplAttributes.IL;
        }

        internal BlobBuilder GetMethodSignatureBlob() =>
            MetadataSignatureHelper.MethodSignatureEncoder(_module, _parameterTypes, ReturnType, !IsStatic);

        protected override bool InitLocalsCore { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        protected override GenericTypeParameterBuilder[] DefineGenericParametersCore(params string[] names) => throw new NotImplementedException();
        protected override ParameterBuilder DefineParameterCore(int position, ParameterAttributes attributes, string? strParamName) => throw new NotImplementedException();
        protected override ILGenerator GetILGeneratorCore(int size) => throw new NotImplementedException();
        protected override void SetCustomAttributeCore(ConstructorInfo con, ReadOnlySpan<byte> binaryAttribute)
        {
            // Handle pseudo custom attributes
            switch (con.ReflectedType!.FullName)
            {
                case "System.Runtime.CompilerServices.MethodImplAttribute":
                    int implValue = BinaryPrimitives.ReadUInt16LittleEndian(binaryAttribute.Slice(2));
                    _methodImplFlags |= (MethodImplAttributes)implValue;
                    return;
                case "System.Runtime.InteropServices.DllImportAttribute":
                    {
                        _dllImportData = DllImportData.CreateDllImportData(CustomAttributeInfo.DecodeCustomAttribute(con, binaryAttribute), out var preserveSig);
                        _attributes |= MethodAttributes.PinvokeImpl;
                        if (preserveSig)
                        {
                            _methodImplFlags |= MethodImplAttributes.PreserveSig;
                        }
                    }
                    return;
                case "System.Runtime.InteropServices.PreserveSigAttribute":
                    _methodImplFlags |= MethodImplAttributes.PreserveSig;
                    return;
                case "System.Runtime.CompilerServices.SpecialNameAttribute":
                    _attributes |= MethodAttributes.SpecialName;
                    return;
                case "System.Security.SuppressUnmanagedCodeSecurityAttribute":
                    _attributes |= MethodAttributes.HasSecurity;
                    break;
            }

            _customAttributes ??= new List<CustomAttributeWrapper>();
            _customAttributes.Add(new CustomAttributeWrapper(con, binaryAttribute));
        }

        protected override void SetImplementationFlagsCore(MethodImplAttributes attributes)
        {
            _methodImplFlags = attributes;
        }
        protected override void SetSignatureCore(Type? returnType, Type[]? returnTypeRequiredCustomModifiers, Type[]? returnTypeOptionalCustomModifiers, Type[]? parameterTypes,
            Type[][]? parameterTypeRequiredCustomModifiers, Type[][]? parameterTypeOptionalCustomModifiers) => throw new NotImplementedException();
        public override string Name => _name;
        public override MethodAttributes Attributes => _attributes;
        public override CallingConventions CallingConvention => _callingConventions;
        public override TypeBuilder DeclaringType => _declaringType;
        public override Module Module => _module;
        public override bool ContainsGenericParameters { get => throw new NotSupportedException(SR.NotSupported_DynamicModule); }
        public override bool IsGenericMethod { get => throw new NotImplementedException(); }
        public override bool IsGenericMethodDefinition { get => throw new NotImplementedException(); }
        public override bool IsSecurityCritical => true;
        public override bool IsSecuritySafeCritical => false;
        public override bool IsSecurityTransparent => false;
        public override int MetadataToken { get => throw new NotImplementedException(); }
        public override RuntimeMethodHandle MethodHandle => throw new NotSupportedException(SR.NotSupported_DynamicModule);
        public override Type? ReflectedType { get => throw new NotImplementedException(); }
        public override ParameterInfo ReturnParameter { get => throw new NotImplementedException(); }
        public override Type ReturnType => _returnType;
        public override ICustomAttributeProvider ReturnTypeCustomAttributes { get => throw new NotImplementedException(); }

        public override MethodInfo GetBaseDefinition() => this;

        public override object[] GetCustomAttributes(bool inherit) => throw new NotSupportedException(SR.NotSupported_DynamicModule);

        public override object[] GetCustomAttributes(Type attributeType, bool inherit) => throw new NotSupportedException(SR.NotSupported_DynamicModule);

        public override Type[] GetGenericArguments()
            => throw new NotImplementedException();

        public override MethodInfo GetGenericMethodDefinition()
            => throw new NotImplementedException();

        public override int GetHashCode()
            => throw new NotImplementedException();

        public override MethodImplAttributes GetMethodImplementationFlags()
            => _methodImplFlags;

        public override ParameterInfo[] GetParameters()
            => throw new NotImplementedException();

        public override object Invoke(object? obj, BindingFlags invokeAttr, Binder? binder, object?[]? parameters, CultureInfo? culture)
             => throw new NotSupportedException(SR.NotSupported_DynamicModule);

        public override bool IsDefined(Type attributeType, bool inherit) => throw new NotSupportedException(SR.NotSupported_DynamicModule);

        [RequiresDynamicCode("The native code for this instantiation might not be available at runtime.")]
        [RequiresUnreferencedCodeAttribute("If some of the generic arguments are annotated (either with DynamicallyAccessedMembersAttribute, or generic constraints), trimming can't validate that the requirements of those annotations are met.")]
        public override MethodInfo MakeGenericMethod(params System.Type[] typeArguments)
            => throw new NotImplementedException();
    }

    internal sealed class DllImportData
    {
        private readonly string _moduleName;
        private readonly string? _entryPoint;
        private readonly MethodImportAttributes _flags;
        internal DllImportData(string moduleName, string? entryPoint, MethodImportAttributes flags)
        {
            _moduleName = moduleName;
            _entryPoint = entryPoint;
            _flags = flags;
        }

        public string ModuleName => _moduleName;

        public string? EntryPoint => _entryPoint;

        public MethodImportAttributes Flags => _flags;

        internal static DllImportData CreateDllImportData(CustomAttributeInfo attr, out bool preserveSig)
        {
            string? moduleName = (string?)attr._ctorArgs[0];
            if (moduleName == null || moduleName.Length == 0)
            {
                throw new ArgumentException(SR.Argument_DllNameCannotBeEmpty);
            }

            MethodImportAttributes importAttributes = MethodImportAttributes.None;
            string? entryPoint = null;
            preserveSig = true;
            for (int i = 0; i < attr._namedParamNames.Length; ++i)
            {
                string name = attr._namedParamNames[i];
                object value = attr._namedParamValues[i]!;
                switch (name)
                {
                    case "PreserveSig":
                        preserveSig = (bool)value;
                        break;
                    case "CallingConvention":
                        importAttributes |= (CallingConvention)value switch
                        {
                            CallingConvention.Cdecl => MethodImportAttributes.CallingConventionCDecl,
                            CallingConvention.FastCall => MethodImportAttributes.CallingConventionFastCall,
                            CallingConvention.StdCall => MethodImportAttributes.CallingConventionStdCall,
                            CallingConvention.ThisCall => MethodImportAttributes.CallingConventionThisCall,
                            _=> MethodImportAttributes.CallingConventionWinApi // Roslyn defaults with this
                        };
                        break;
                    case "CharSet":
                        importAttributes |= (CharSet)value switch
                        {
                            CharSet.Ansi => MethodImportAttributes.CharSetAnsi,
                            CharSet.Auto => MethodImportAttributes.CharSetAuto,
                            CharSet.Unicode => MethodImportAttributes.CharSetUnicode,
                            _ => MethodImportAttributes.CharSetAuto
                        };
                        break;
                    case "EntryPoint":
                        entryPoint = (string?)value;
                        break;
                    case "ExactSpelling":
                        if ((bool)value)
                        {
                            importAttributes |= MethodImportAttributes.ExactSpelling;
                        }
                        break;
                    case "SetLastError":
                        if ((bool)value)
                        {
                            importAttributes |= MethodImportAttributes.SetLastError;
                        }
                        break;
                    case "BestFitMapping":
                        if ((bool)value)
                        {
                            importAttributes |= MethodImportAttributes.BestFitMappingEnable;
                        }
                        else
                        {
                            importAttributes |= MethodImportAttributes.BestFitMappingDisable;
                        }
                        break;
                    case "ThrowOnUnmappableChar":
                        if ((bool)value)
                        {
                            importAttributes |= MethodImportAttributes.ThrowOnUnmappableCharEnable;
                        }
                        else
                        {
                            importAttributes |= MethodImportAttributes.ThrowOnUnmappableCharDisable;
                        }
                        break;
                }
            }

            return new DllImportData(moduleName, entryPoint, importAttributes);
        }
    }
}
