# Ripasso Gnome Search Provider

WIP search provider for GNOME using ripasso.

## Setting a custom PASSWORD_STORE_DIR

Use `systemctl --user edit org.gnome.Ripasso.SearchProvider.service`
to create an override file that contains the following:

```ini
[Service]
Environment="PASSWORD_STORE_DIR=/path/to/password-store"
```
