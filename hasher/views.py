from django.shortcuts import render
from django.contrib import messages
from .forms import (
    TextHashForm, FileHashForm, MacForm, MacVerifyForm,
    TamperMessageForm, HashDistForm,
    MacFileForm, MacVerifyFileForm
)
from .utils import ascon_hash256
from .ascon import ascon_mac

def index(request):
    action = request.POST.get('action') if request.method == 'POST' else None

    text_form_instance = TextHashForm(request.POST if action == 'text_submit' else None)
    file_form_instance = FileHashForm(request.POST if action == 'file_submit' else None, 
                                      request.FILES if action == 'file_submit' else None)
    mac_form_instance = MacForm(request.POST if action == 'mac_generate_submit' else None)
    mac_verify_form_instance = MacVerifyForm(request.POST if action == 'mac_verify_submit' else None)
    
    mac_file_form_instance = MacFileForm(request.POST if action == 'mac_generate_file_submit' else None,
                                         request.FILES if action == 'mac_generate_file_submit' else None)
    mac_verify_file_form_instance = MacVerifyFileForm(request.POST if action == 'mac_verify_file_submit' else None,
                                                      request.FILES if action == 'mac_verify_file_submit' else None)

    if action == 'tamper_verify_submit':
        tamper_form_instance = TamperMessageForm(request.POST)
    else:
        initial_tamper_data = {}
        if request.session.get('forgery_original_message'):
            initial_tamper_data['tampered_message'] = request.session.get('forgery_original_message')
        tamper_form_instance = TamperMessageForm(initial=initial_tamper_data)

    hash_dist_form_instance = HashDistForm(request.POST if action == 'hash_dist_submit' else None)

    context = {
        'text_form': text_form_instance,
        'file_form': file_form_instance,
        'mac_form': mac_form_instance,
        'mac_verify_form': mac_verify_form_instance,
        'mac_file_form': mac_file_form_instance,
        'mac_verify_file_form': mac_verify_file_form_instance,
        'tamper_form': tamper_form_instance,
        'hash_dist_form': hash_dist_form_instance,
        'result': None,
        'input_type': None,
        'input_info': None,
        'mac_tag_generated': None,
        'mac_verification_status': None,
        'forgery_original_message': request.session.get('forgery_original_message'),
        'forgery_key_hex': request.session.get('forgery_key_hex'),
        'forgery_original_tag_hex': request.session.get('forgery_original_tag_hex'),
        'forgery_tampered_message': None, 
        'forgery_verification_status': None,
        'hash_dist_data_points': [],
        'active_tab': 'text-hash-pane', 
        'mac_input_type': None, 
        'mac_input_info': None, 
    }
    
    if request.method == 'POST':
        context['active_tab'] = request.POST.get('active_tab_on_submit', context['active_tab'])

        if action == 'text_submit':
            if text_form_instance.is_valid():
                text_input_str = text_form_instance.cleaned_data['text_input'] # This is expected to be a hex string
                try:
                    # --- MODIFICATION START ---
                    # Directly convert the input string (expected to be hex) to bytes
                    input_bytes_for_hash = bytes.fromhex(text_input_str)
                    # --- MODIFICATION END ---

                    hash_bytes = ascon_hash256(input_bytes_for_hash)
                    context['result'] = hash_bytes.hex()
                    
                    # --- MODIFICATION START for context display ---
                    context['input_type'] = 'Text Input (Hexadecimal String)'
                    display_hex_input = (text_input_str[:100] + '...') if len(text_input_str) > 100 else text_input_str
                    context['input_info'] = (f'Hex Input: "{display_hex_input}"<br>'
                                             f'Bytes Hashed (from hex): {len(input_bytes_for_hash)}')
                    if not text_input_str: # Handle empty input specifically for info
                        context['input_info'] = ('Hex Input: "" (Empty String)<br>'
                                                 'Bytes Hashed (from hex): 0')
                    # --- MODIFICATION END for context display ---
                except ValueError: # This catches errors if text_input_str is not a valid hex string
                    messages.error(request, 'Invalid hexadecimal string provided. Please ensure your input contains only hex characters (0-9, a-f, A-F) and has an even length if not empty.')
                    context['result'] = None # Clear any previous result
                except Exception as e: 
                    messages.error(request, f'Hashing error: {str(e)}')
                    context['result'] = None # Clear any previous result
        
        # ... (rest of elif blocks for file_submit, mac_generate_submit, etc. remain the same as the last full version) ...
        elif action == 'file_submit':
            if file_form_instance.is_valid():
                file_input = file_form_instance.cleaned_data.get('file_input')
                if file_input:
                    try:
                        content = b''.join(chunk for chunk in file_input.chunks())
                        hash_bytes = ascon_hash256(content)
                        context['result'] = hash_bytes.hex()
                        context['input_type'] = 'File Input'
                        context['input_info'] = f'Filename: {file_input.name}, Size: {file_input.size} bytes'
                    except Exception as e:
                        messages.error(request, f'File hashing error: {str(e)}')

        elif action == 'mac_generate_submit': 
            if mac_form_instance.is_valid():
                try:
                    key_hex = mac_form_instance.cleaned_data['key']
                    message_str = mac_form_instance.cleaned_data['message']
                    key_bytes = bytes.fromhex(key_hex)
                    message_bytes = message_str.encode('utf-8')
                    
                    tag_bytes = ascon_mac(key_bytes, message_bytes, variant="Ascon-Mac", taglength=16)
                    context['mac_tag_generated'] = tag_bytes.hex()
                    context['mac_input_type'] = "Text Message"
                    context['mac_input_info'] = f"Message length: {len(message_bytes)} bytes"
                    messages.success(request, "ASCON-MAC tag generated successfully for text message.")

                    request.session['forgery_original_message'] = message_str
                    request.session['forgery_key_hex'] = key_hex
                    request.session['forgery_original_tag_hex'] = context['mac_tag_generated']
                    
                    context['forgery_original_message'] = message_str
                    context['forgery_key_hex'] = key_hex
                    context['forgery_original_tag_hex'] = context['mac_tag_generated']
                    context['tamper_form'] = TamperMessageForm(initial={'tampered_message': message_str})

                except ValueError:
                    messages.error(request, "Invalid hex string for key.")
                except Exception as e:
                    messages.error(request, f'MAC generation error: {str(e)}')

        elif action == 'mac_generate_file_submit':
            if mac_file_form_instance.is_valid():
                try:
                    key_hex = mac_file_form_instance.cleaned_data['key']
                    message_file = mac_file_form_instance.cleaned_data['message_file']
                    
                    key_bytes = bytes.fromhex(key_hex)
                    file_content_bytes = b''.join(chunk for chunk in message_file.chunks())
                    
                    tag_bytes = ascon_mac(key_bytes, file_content_bytes, variant="Ascon-Mac", taglength=16)
                    context['mac_tag_generated'] = tag_bytes.hex()
                    context['mac_input_type'] = "File Message"
                    context['mac_input_info'] = f"Filename: {message_file.name}, Size: {message_file.size} bytes"
                    messages.success(request, f"ASCON-MAC tag generated successfully for file '{message_file.name}'.")
                    
                    if 'forgery_original_message' in request.session: 
                        del request.session['forgery_original_message']
                        del request.session['forgery_key_hex']
                        del request.session['forgery_original_tag_hex']
                    context['forgery_original_message'] = None
                    context['forgery_key_hex'] = None
                    context['forgery_original_tag_hex'] = None
                    context['tamper_form'] = TamperMessageForm()

                except ValueError:
                    messages.error(request, "Invalid hex string for key.")
                except Exception as e:
                    messages.error(request, f'File MAC generation error: {str(e)}')
        
        elif action == 'mac_verify_submit': 
            if mac_verify_form_instance.is_valid():
                try:
                    key_hex = mac_verify_form_instance.cleaned_data['key']
                    message_str = mac_verify_form_instance.cleaned_data['message']
                    tag_hex_to_verify = mac_verify_form_instance.cleaned_data['tag']

                    key_bytes = bytes.fromhex(key_hex)
                    message_bytes = message_str.encode('utf-8')
                    tag_to_verify_bytes = bytes.fromhex(tag_hex_to_verify)

                    calculated_tag_bytes = ascon_mac(key_bytes, message_bytes, variant="Ascon-Mac", taglength=16)
                    context['mac_input_type'] = "Text Message Verification"
                    context['mac_input_info'] = f"Message length: {len(message_bytes)} bytes, Submitted Tag: {tag_hex_to_verify}"
                    if calculated_tag_bytes == tag_to_verify_bytes:
                        context['mac_verification_status'] = "SUCCESS: Tag is valid."
                        messages.success(request, context['mac_verification_status'])
                    else:
                        context['mac_verification_status'] = "FAILURE: Tag is invalid."
                        messages.error(request, context['mac_verification_status'])
                except ValueError:
                    messages.error(request, "Invalid hex string for key or tag.")
                except Exception as e:
                    messages.error(request, f'MAC verification error: {str(e)}')

        elif action == 'mac_verify_file_submit':
            if mac_verify_file_form_instance.is_valid():
                try:
                    key_hex = mac_verify_file_form_instance.cleaned_data['key']
                    message_file = mac_verify_file_form_instance.cleaned_data['message_file']
                    tag_hex_to_verify = mac_verify_file_form_instance.cleaned_data['tag']

                    key_bytes = bytes.fromhex(key_hex)
                    file_content_bytes = b''.join(chunk for chunk in message_file.chunks())
                    tag_to_verify_bytes = bytes.fromhex(tag_hex_to_verify)
                    
                    calculated_tag_bytes = ascon_mac(key_bytes, file_content_bytes, variant="Ascon-Mac", taglength=16)
                    context['mac_input_type'] = "File Message Verification"
                    context['mac_input_info'] = f"Filename: {message_file.name}, Size: {message_file.size} bytes, Submitted Tag: {tag_hex_to_verify}"
                    if calculated_tag_bytes == tag_to_verify_bytes:
                        context['mac_verification_status'] = "SUCCESS: Tag is valid."
                        messages.success(request, f"Tag verification successful for file '{message_file.name}'.")
                    else:
                        context['mac_verification_status'] = "FAILURE: Tag is invalid."
                        messages.error(request, f"Tag verification failed for file '{message_file.name}'.")
                except ValueError:
                    messages.error(request, "Invalid hex string for key or tag.")
                except Exception as e:
                    messages.error(request, f'File MAC verification error: {str(e)}')

        elif action == 'tamper_verify_submit':
            if tamper_form_instance.is_valid(): 
                original_message_str = tamper_form_instance.cleaned_data['original_message']
                original_key_hex = tamper_form_instance.cleaned_data['original_key']
                original_tag_hex = tamper_form_instance.cleaned_data['original_tag']
                tampered_message_str = tamper_form_instance.cleaned_data['tampered_message']
                
                context['forgery_original_message'] = original_message_str
                context['forgery_key_hex'] = original_key_hex
                context['forgery_original_tag_hex'] = original_tag_hex
                context['forgery_tampered_message'] = tampered_message_str 

                try:
                    if not (original_key_hex and original_tag_hex):
                        messages.error(request, "Original key or tag for forgery simulation is missing. Please generate a text MAC first.")
                    else:
                        key_bytes = bytes.fromhex(original_key_hex)
                        tampered_message_bytes = tampered_message_str.encode('utf-8')
                        original_tag_bytes = bytes.fromhex(original_tag_hex)
                        
                        calculated_tag_for_tampered_bytes = ascon_mac(key_bytes, tampered_message_bytes, variant="Ascon-Mac", taglength=16)

                        if calculated_tag_for_tampered_bytes == original_tag_bytes:
                            if original_message_str == tampered_message_str:
                                 context['forgery_verification_status'] = "VERIFICATION SUCCESS: Message was not altered. Tag is valid."
                            else:
                                 context['forgery_verification_status'] = "VERIFICATION SUCCESS (UNEXPECTED): The tampered message produces the same original tag. This is highly unlikely for a secure MAC unless the tampering was trivial or reverted."
                            messages.success(request, context['forgery_verification_status'])
                        else:
                            context['forgery_verification_status'] = "VERIFICATION FAILURE: The tampered message does NOT match the original tag. Integrity compromised!"
                            messages.error(request, context['forgery_verification_status'])
                except ValueError:
                    messages.error(request, "Invalid hex string for key or original tag in forgery demo.")
                except Exception as e:
                    messages.error(request, f'Forgery detection error: {str(e)}')

        elif action == 'hash_dist_submit':
            if hash_dist_form_instance.is_valid():
                base_string = hash_dist_form_instance.cleaned_data['base_string']
                num_hashes = hash_dist_form_instance.cleaned_data['num_hashes']
                
                current_hash_dist_points = []
                try:
                    for i in range(num_hashes):
                        message_to_hash_str = f"{base_string}{i}"
                        message_bytes_for_dist = message_to_hash_str.encode('utf-8')
                        h_bytes = ascon_hash256(message_bytes_for_dist)
                        
                        if len(h_bytes) >= 4:
                            x = int.from_bytes(h_bytes[0:2], 'little')
                            y = int.from_bytes(h_bytes[2:4], 'little')
                            current_hash_dist_points.append({'x': x, 'y': y})
                    
                    if current_hash_dist_points:
                        context['hash_dist_data_points'] = current_hash_dist_points
                        messages.success(request, f"Generated {len(current_hash_dist_points)} points for hash distribution.")
                    else:
                        messages.warning(request, "No points generated for hash distribution.")
                except Exception as e:
                    messages.error(request, f'Hash distribution data generation error: {str(e)}')
    else: 
        if not request.GET.get('preserve_forgery') and 'forgery_original_message' in request.session :
             if 'forgery_original_message' in request.session: del request.session['forgery_original_message']
             if 'forgery_key_hex' in request.session: del request.session['forgery_key_hex']
             if 'forgery_original_tag_hex' in request.session: del request.session['forgery_original_tag_hex']
        
        context['forgery_original_message'] = request.session.get('forgery_original_message')
        context['forgery_key_hex'] = request.session.get('forgery_key_hex')
        context['forgery_original_tag_hex'] = request.session.get('forgery_original_tag_hex')
        if context['forgery_original_message']: 
            context['tamper_form'] = TamperMessageForm(initial={'tampered_message': context['forgery_original_message']})


    return render(request, 'hasher/index.html', context)