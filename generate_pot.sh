#!/bin/bash

xgettext cursive/src/*rs -kgettext --sort-output -o cursive/res/ripasso-cursive.pot

msgmerge --update cursive/res/sv.po cursive/res/ripasso-cursive.pot
msgmerge --update cursive/res/nb.po cursive/res/ripasso-cursive.pot
msgmerge --update cursive/res/nn.po cursive/res/ripasso-cursive.pot
