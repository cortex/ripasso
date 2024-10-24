# Ripasso Gnome Search Provider

This module builds a gnome search provider that allows you to simply start typing for a password in the gnome overview and get results from Ripasso.

![image](https://github.com/user-attachments/assets/612eb516-cbb1-4e6f-b8c3-046b413a1233)

Pressing enter when an entry is highlighted will copy it to the clipboard, erasing it after 40 seconds.

## Installation
Run the `./install.sh` script and restart your Gnome session. The search provider and it's priority can be enabled/disabled in Gnome Settings under Search.

## Setting a custom PASSWORD_STORE_DIR

Use `systemctl --user edit org.gnome.Ripasso.SearchProvider.service`
to create an override file that contains the following:

```ini
[Service]
Environment="PASSWORD_STORE_DIR=/path/to/password-store"
```
