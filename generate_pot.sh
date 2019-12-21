#!/bin/bash

xgettext cursive/src/*rs -kgettext --sort-output -o cursive/res/ripasso-cursive.pot

msgmerge --update cursive/res/sv.po cursive/res/ripasso-cursive.pot
