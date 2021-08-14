## Updating an existing translation

If you spot a typo or something else that needs to be improved, these are the steps:

```
git clone git@github.com:cortex/ripasso.git
cd ripasso
poedit cursive/res/fr.po
```

[poedit](https://poedit.net/) is a stand-alone program to edit translation files. There is other
alternatives, but poedit is quite easy to use.

After that you just need to submit a [pull request on github](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
with your changes in them.

## Adding a new translation

If you want to translate ripasso to your language here is how:

1. Check out the source code `git clone git@github.com:cortex/ripasso.git`
2. Edit `generate_pot.sh` and add a line at the bottom for the new language
3. Execute `./generate_pot.sh`
4. Translate the strings `poedit cursive/res/fr.po`

After that you just need to submit a [pull request on github](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
with your changes. Poedit will generate a `.mo` file in addition to the
`.po` file, that is only a binary representation of the information in the `.po` file
and should not be included in the pull request.
