from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add a digest column for hashed static tokens.

    Existing rows keep their plaintext in ``token`` until they are either
    consumed through verification or converted by the
    ``migratestatictokens`` management command, so this migration performs no
    data movement and is safe to run while the service is up.
    """

    dependencies = [
        ('otp_static', '0003_add_timestamps'),
    ]

    operations = [
        migrations.AddField(
            model_name='statictoken',
            name='digest',
            field=models.CharField(blank=True, db_index=True, default='', max_length=64),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='statictoken',
            name='token',
            field=models.CharField(blank=True, db_index=True, max_length=16),
        ),
    ]
