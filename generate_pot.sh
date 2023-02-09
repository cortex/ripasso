#!/bin/bash

xgettext cursive/src/*rs -kgettext --sort-output -o cursive/res/ripasso-cursive.pot

touch cursive/res/sv.po && msgmerge --update cursive/res/sv.po cursive/res/ripasso-cursive.pot
touch cursive/res/nb.po && msgmerge --update cursive/res/nb.po cursive/res/ripasso-cursive.pot
touch cursive/res/nn.po && msgmerge --update cursive/res/nn.po cursive/res/ripasso-cursive.pot
touch cursive/res/fr.po && msgmerge --update cursive/res/fr.po cursive/res/ripasso-cursive.pot
touch cursive/res/it.po && msgmerge --update cursive/res/it.po cursive/res/ripasso-cursive.pot
touch cursive/res/de.po && msgmerge --update cursive/res/de.po cursive/res/ripasso-cursive.pot
touch cursive/res/ru.po && msgmerge --update cursive/res/ru.po cursive/res/ripasso-cursive.pot
