from django import forms

class TextHashForm(forms.Form):
    text_input = forms.CharField(
        label='Text to Hash (Hexadecimal String Input)', # Updated label
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Enter a hexadecimal string (e.g., 616263 for "abc", or 000102). Leave empty for empty hash.' # Updated placeholder
        }),
        required=False # Allows empty string, which bytes.fromhex('') handles as b''
    )

# ... (Rest of the forms: FileHashForm, MacForm, MacVerifyForm, MacFileForm, MacVerifyFileForm, TamperMessageForm, HashDistForm remain unchanged from the last version)

class FileHashForm(forms.Form):
    file_input = forms.FileField(
        label='Select File to Hash',
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '*/*'
        }),
        required=False
    )

class MacForm(forms.Form): # For Text-based MAC Generation
    key = forms.CharField(
        label='Secret Key (16 bytes hex, e.g., 001122...ff)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Key must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Key must be exactly 32 hex characters (16 bytes).'}
    )
    message = forms.CharField(
        label='Message',
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter message for MAC generation...'}),
        required=False
    )

class MacVerifyForm(forms.Form): # For Text-based MAC Verification
    key = forms.CharField(
        label='Secret Key (16 bytes hex)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Key must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Key must be exactly 32 hex characters (16 bytes).'}
    )
    message = forms.CharField(
        label='Message',
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter original message for MAC verification...'}),
        required=False
    )
    tag = forms.CharField(
        label='Tag to Verify (16 bytes hex, e.g., aabbcc...ee)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Tag must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Tag must be exactly 32 hex characters (16 bytes).'}
    )

class MacFileForm(forms.Form): # For File-based MAC Generation
    key = forms.CharField(
        label='Secret Key (16 bytes hex, e.g., 001122...ff)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Key must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Key must be exactly 32 hex characters (16 bytes).'}
    )
    message_file = forms.FileField(
        label='Message File',
        widget=forms.FileInput(attrs={'class': 'form-control'}),
        required=True
    )

class MacVerifyFileForm(forms.Form): # For File-based MAC Verification
    key = forms.CharField(
        label='Secret Key (16 bytes hex)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Key must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Key must be exactly 32 hex characters (16 bytes).'}
    )
    message_file = forms.FileField(
        label='Message File',
        widget=forms.FileInput(attrs={'class': 'form-control'}),
        required=True
    )
    tag = forms.CharField(
        label='Tag to Verify (16 bytes hex, e.g., aabbcc...ee)',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Exactly 32 hexadecimal characters'}),
        max_length=32,
        min_length=32,
        error_messages={'min_length': 'Tag must be exactly 32 hex characters (16 bytes).',
                        'max_length': 'Tag must be exactly 32 hex characters (16 bytes).'}
    )

class TamperMessageForm(forms.Form):
    original_message = forms.CharField(widget=forms.HiddenInput(), required=False)
    original_key = forms.CharField(widget=forms.HiddenInput(), required=False)
    original_tag = forms.CharField(widget=forms.HiddenInput(), required=False)
    tampered_message = forms.CharField(
        label='Message (edit to simulate tampering)',
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        required=False,
        strip=False # Preserve whitespace
    )

class HashDistForm(forms.Form):
    base_string = forms.CharField(
        label='Base String for Hash Distribution',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., ASCONTest'}),
        initial='ASCON',
        required=True
    )
    num_hashes = forms.IntegerField(
        label='Number of Hashes to Generate (10-500)',
        min_value=10,
        max_value=500,
        initial=50,
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )