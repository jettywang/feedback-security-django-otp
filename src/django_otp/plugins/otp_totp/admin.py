from django.contrib import admin
from django.contrib.admin.sites import AlreadyRegistered
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from django_otp.admin import (
    CONFIG_VIEW_DENIED,
    CONFIG_VIEW_GRANTED,
    audit_config_access,
    user_has_config_permission,
    user_model_search_fields,
)
from django_otp.conf import settings
from django_otp.qr import write_qrcode_image

from .models import TOTPDevice


class TOTPDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~django_otp.plugins.otp_totp.models.TOTPDevice`.

    Viewing a device's secret key or its QR code requires the dedicated
    ``otp_totp.view_totpdevice_config`` permission, in addition to the normal
    view or change permission for the model. Ordinary device metadata remains
    available with just the normal model permissions.
    """

    User = get_user_model()
    candidate_search_field = [User.USERNAME_FIELD, 'email']

    list_display = ['user', 'name', 'created_at', 'last_used_at', 'confirmed']
    list_filter = ['created_at', 'last_used_at', 'confirmed']
    search_fields, search_help_text = user_model_search_fields(candidate_search_field)

    raw_id_fields = ['user']
    readonly_fields = ['created_at', 'last_used_at', 'qrcode_link']
    radio_fields = {'digits': admin.HORIZONTAL}

    def user_can_view_config(self, request):
        return user_has_config_permission(request.user, TOTPDevice)

    def _show_key(self, request, obj):
        return obj is None or (
            not settings.OTP_ADMIN_HIDE_SENSITIVE_DATA
            and self.user_can_view_config(request)
        )

    def render_change_form(
        self, request, context, add=False, change=False, form_url='', obj=None
    ):
        if (
            request.method == 'GET'
            and not add
            and obj is not None
            and self._show_key(request, obj)
        ):
            audit_config_access(self, CONFIG_VIEW_GRANTED, obj.pk)

        return super().render_change_form(
            request, context, add=add, change=change, form_url=form_url, obj=obj
        )

    def get_list_display(self, request):
        list_display = super().get_list_display(request)
        if (
            not settings.OTP_ADMIN_HIDE_SENSITIVE_DATA
            and self.user_can_view_config(request)
        ):
            list_display = [*list_display, 'qrcode_link']
        return list_display

    def get_fieldsets(self, request, obj=None):
        # Show the key value only for adding new objects or when sensitive data
        # is not hidden and the user has the dedicated configuration
        # permission.
        if self._show_key(request, obj):
            configuration_fields = ['key', 'step', 't0', 'digits', 'tolerance']
        else:
            configuration_fields = ['step', 't0', 'digits', 'tolerance']
        fieldsets = [
            (
                'Identity',
                {
                    'fields': ['user', 'name', 'confirmed'],
                },
            ),
            (
                'Timestamps',
                {
                    'fields': ['created_at', 'last_used_at'],
                },
            ),
            (
                'Configuration',
                {
                    'fields': configuration_fields,
                },
            ),
            (
                'State',
                {
                    'fields': ['drift'],
                },
            ),
            (
                'Throttling',
                {
                    'fields': [
                        'throttling_failure_timestamp',
                        'throttling_failure_count',
                    ],
                },
            ),
        ]
        # Show the QR code link only for existing objects when sensitive data
        # is not hidden and the user has the dedicated configuration
        # permission.
        if (
            obj
            and not settings.OTP_ADMIN_HIDE_SENSITIVE_DATA
            and self.user_can_view_config(request)
        ):
            fieldsets.append(
                (
                    None,
                    {
                        'fields': ['qrcode_link'],
                    },
                ),
            )
        return fieldsets

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.select_related('user')

        return queryset

    #
    # Columns
    #

    @admin.display(description="QR Code")
    def qrcode_link(self, device):
        try:
            href = reverse('admin:otp_totp_totpdevice_config', kwargs={'pk': device.pk})
            link = format_html('<a href="{}">qrcode</a>', href)
        except Exception:
            link = ''

        return link

    #
    # Custom views
    #

    def get_urls(self):
        urls = [
            path(
                '<int:pk>/config/',
                self.admin_site.admin_view(self.config_view),
                name='otp_totp_totpdevice_config',
            ),
            path(
                '<int:pk>/qrcode/',
                self.admin_site.admin_view(self.qrcode_view),
                name='otp_totp_totpdevice_qrcode',
            ),
        ] + super().get_urls()

        return urls

    def _authorize_config_view(self, request, device):
        """
        Enforce the dedicated configuration permission and record a denial.

        Raises :exc:`~django.core.exceptions.PermissionDenied` after recording
        a denied event unless the user may see the secret key and QR code. A
        granted event is recorded by the caller once the display actually
        succeeds.
        """
        allowed = (
            not settings.OTP_ADMIN_HIDE_SENSITIVE_DATA
            and self.has_view_or_change_permission(request, device)
            and self.user_can_view_config(request)
        )
        if not allowed:
            audit_config_access(self, CONFIG_VIEW_DENIED, device.pk)
            raise PermissionDenied()

    def config_view(self, request, pk):
        device = TOTPDevice.objects.get(pk=pk)
        self._authorize_config_view(request, device)

        context = dict(
            self.admin_site.each_context(request),
            device=device,
        )
        audit_config_access(self, CONFIG_VIEW_GRANTED, device.pk)

        return TemplateResponse(request, 'otp_totp/admin/config.html', context)

    def qrcode_view(self, request, pk):
        device = TOTPDevice.objects.get(pk=pk)
        self._authorize_config_view(request, device)

        try:
            response = HttpResponse(content_type='image/svg+xml')
            write_qrcode_image(device.config_url, response)
        except ModuleNotFoundError:
            response = HttpResponse('', status=503)
        else:
            audit_config_access(self, CONFIG_VIEW_GRANTED, device.pk)

        return response


try:
    admin.site.register(TOTPDevice, TOTPDeviceAdmin)
except AlreadyRegistered:
    # A useless exception from a double import
    pass
