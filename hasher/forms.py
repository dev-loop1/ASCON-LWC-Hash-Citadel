from django import forms

class TextHashForm(forms.Form):
    text_input = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 5,
            'placeholder': 'Enter text to hash...'
        }),
        required=False
    )

class FileHashForm(forms.Form):
    file_input = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '*/*'  # Accept all file types
        }),
        required=False
    )