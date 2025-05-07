use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(JamEncode)]
pub fn derive_jam_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => panic!("JamEncode can only derived for structs"),
    };

    let size_hint_fields = match fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|f| {
                let name = &f.ident;
                quote! { self.#name.size_hint() }
            })
            .collect::<Vec<_>>(),
        Fields::Unnamed(fields) => fields
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let index = syn::Index::from(i);
                quote! { self.#index.size_hint() }
            })
            .collect::<Vec<_>>(),
        Fields::Unit => vec![],
    };

    let encode_fields = match fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|f| {
                let name = &f.ident;
                quote! { self.#name.encode_to(dest)?; }
            })
            .collect::<Vec<_>>(),
        Fields::Unnamed(fields) => fields
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let index = syn::Index::from(i);
                quote! { self.#index.encode_to(dest)?; }
            })
            .collect::<Vec<_>>(),
        Fields::Unit => vec![],
    };

    let expanded = quote! {
        impl #impl_generics JamEncode for #name #ty_generics #where_clause {
            fn size_hint(&self) -> usize {
                0 #(+ #size_hint_fields)*
            }

            fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
                #(#encode_fields)*
                Ok(())
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(JamDecode)]
pub fn derive_jam_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => panic!("JamDecode can only be derived for structs"),
    };

    let decode_fields = match fields {
        Fields::Named(fields) => {
            let field_names = fields.named.iter().map(|f| &f.ident);
            let field_types = fields.named.iter().map(|f| &f.ty);
            quote! {
                Ok(Self {
                    #(#field_names: <#field_types>::decode(input)?,)*
                })
            }
        }
        Fields::Unnamed(fields) => {
            let field_types = fields.unnamed.iter().map(|f| &f.ty);
            quote! {
                Ok(Self(
                    #(<#field_types>::decode(input)?,)*
                ))
            }
        }
        Fields::Unit => {
            quote! { Ok(Self) }
        }
    };

    let expanded = quote! {
        impl #impl_generics JamDecode for #name #ty_generics #where_clause {
            fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
                #decode_fields
            }
        }
    };

    TokenStream::from(expanded)
}
