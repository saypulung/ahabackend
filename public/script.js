$(document).ready(() => {
    toastr.options = {
        "closeButton": false,
        "debug": false,
        "newestOnTop": false,
        "progressBar": true,
        "positionClass": "toast-top-right",
        "preventDuplicates": false,
        "onclick": null,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "5000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };
    const clearFormError = () => {
        const forms = [
            'given_name',
            'family_name',
            'phone',
            'gender',
            'custom_gender',
            'refer_as',
            'email',
            'password',
            'password_confirm',
        ];
        for(var key of forms) {
            const elementId = `#form-help-${key.replace('_', '-')}`;
            $(elementId).html('');
        }
    };
    $('#signup-form').submit((e) => {
        e.preventDefault();
        const formData = $('#signup-form').serialize();
        $.ajax({
            type: 'post',
            url: '',
            dataType: 'json',
            data: formData,
            success: (response, status) => {
                if (status === 'Created') {
                    location.href = '/';
                } else {
                    toastr.warning("There are some error during send your data");
                }
            },
            error: (xhr, status, error) => {
                if (xhr.status === 401) {
                    clearFormError();
                    // validation issue
                    const { responseJSON } =  xhr;
                    const keysJson = Object.keys(responseJSON);
                    for(var key of keysJson) {
                        const elementId = `#form-help-${key.replace('_', '-')}`;
                        $(elementId).html(responseJSON[key]);
                    }
                } else {
                    toastr.error("There are some error during send your data. Please check again.");
                }                
                console.log(error);
                console.log('xhr');
                console.log(xhr);
            },
        });
    });
    $('#form_gender').change(() => {
        const val = $('#form_gender').val();
        if (val === '3') {
            $('.--custom-gender').addClass('show');
            $('.--custom-refer').addClass('show');
            $('#form_custom_gender').focus();
        } else {
            $('.--custom-gender').removeClass('show');
            $('.--custom-refer').removeClass('show');
            $('#form_custom_gender').val('');
            $('#form_refer_as').val('');
        }
    });
})