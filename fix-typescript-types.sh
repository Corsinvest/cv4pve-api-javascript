#!/bin/bash

# replace bool type with boolean
find dist -type f -name '*.d.ts' | xargs sed -i 's/bool\([,)>]\)/boolean\1/g'

# replace int with number type
find dist -type f -name '*.d.ts' | xargs sed -i 's/int\([,)>]\)/number\1/g'

# replace flaot with number type
find dist -type f -name '*.d.ts' | xargs sed -i 's/float\([,)>]\)/number\1/g'