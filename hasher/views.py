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
        text_form = TextHashForm(request.POST)
        file_form = FileHashForm(request.POST, request.FILES)
        
        # Check if text input is provided
        if 'text_submit' in request.POST and text_form.is_valid():
            text_input = text_form.cleaned_data['text_input']
            if text_input:
                # Hash the text input
                hash_bytes = ascon_hash256(text_input.encode('utf-8'))
                result = hash_bytes.hex()
                input_type = 'Text Input'
                input_info = f'Length: {len(text_input)} characters'
            else:
                messages.error(request, 'Please enter some text to hash.')
        
        # Check if file input is provided
        elif 'file_submit' in request.POST and file_form.is_valid():
            file_input = request.FILES.get('file_input')
            if file_input:
                # Read file in chunks to handle large files
                content = b''
                for chunk in file_input.chunks():
                    content += chunk

                # Hash the file content
                hash_bytes = ascon_hash256(content)
                result = hash_bytes.hex()
                input_type = 'File Input'
                input_info = f'Filename: {file_input.name}, Size: {file_input.size} bytes'
            else:
                messages.error(request, 'Please select a file to hash.')
    
    context = {
        'text_form': text_form,
        'file_form': file_form,
        'result': result,
        'input_type': input_type,
        'input_info': input_info
    }
    
    return render(request, 'hasher/index.html', context)