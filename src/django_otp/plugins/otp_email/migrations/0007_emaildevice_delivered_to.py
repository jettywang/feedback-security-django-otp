from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('otp_email', '0006_add_timestamps'),
    ]

    operations = [
        migrations.AddField(
            model_name='emaildevice',
            name='delivered_to',
            field=models.EmailField(
                blank=True,
                help_text='The email address the current token was delivered to',
                max_length=254,
                null=True,
            ),
        ),
    ]
