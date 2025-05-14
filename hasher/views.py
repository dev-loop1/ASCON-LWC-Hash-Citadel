from django.shortcuts import render
from django.contrib import messages
from .forms import TextHashForm, FileHashForm
from .utils import ascon_hash256

def index(request):
    text_form = TextHashForm()
    file_form = FileHashForm()
    result = None
    input_type = None
    input_info = None
    
    if request.method == 'POST':
        # Re-initialize forms with POST data for display if validation fails or for reuse
        text_form = TextHashForm(request.POST)
        file_form = FileHashForm(request.POST, request.FILES)
        
        # Check if text input is provided
        if 'text_submit' in request.POST:
            if text_form.is_valid(): # Ensure form validation passes first
                text_input_str = text_form.cleaned_data['text_input']
                if text_input_str:
                    try:
                        
                        # Convert hex string to bytes
                        input_bytes_for_hash = bytes.fromhex(text_input_str)
                        
                        hash_bytes = ascon_hash256(input_bytes_for_hash)
                        result = hash_bytes.hex()
                        input_type = 'Text Input (interpreted as Hex String)'
                        input_info = f'Hex Input: "{text_input_str}", Bytes Hashed: {len(input_bytes_for_hash)}'
                    except ValueError:
                        messages.error(request, 'Invalid hexadecimal string provided in text input. Please use characters 0-9 and a-f (or A-F).')
                        result = None # Clear previous result if error
                    except Exception as e:
                        messages.error(request, f'An error occurred during hashing: {str(e)}')
                        result = None # Clear previous result if error
                else:
                    messages.error(request, 'Please enter some text (hex string) to hash.')
            # else: if form is not valid, errors will be associated with the form by Django
        
        # Check if file input is provided
        elif 'file_submit' in request.POST:
            if file_form.is_valid(): # Ensure form validation passes first
                file_input = request.FILES.get('file_input') # Using .get() is safer
                if file_input:
                    try:
                        # Read file in chunks to handle large files
                        content = b''
                        for chunk in file_input.chunks():
                            content += chunk

                        # Hash the file content
                        hash_bytes = ascon_hash256(content)
                        result = hash_bytes.hex()
                        input_type = 'File Input'
                        input_info = f'Filename: {file_input.name}, Size: {file_input.size} bytes'
                    except Exception as e:
                        messages.error(request, f'An error occurred during file hashing: {str(e)}')
                        result = None # Clear previous result if error
                else:
                    messages.error(request, 'Please select a file to hash.')
            # else: if form is not valid, errors will be associated with the form by Django
    
    context = {
        'text_form': text_form,
        'file_form': file_form,
        'result': result,
        'input_type': input_type,
        'input_info': input_info
    }
    
    return render(request, 'hasher/index.html', context)