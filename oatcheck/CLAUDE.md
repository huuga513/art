# Oatcheck Coding Guidelines

## Comments
所有注释都应使用英文编写，包括代码注释，git提交信息

## Exceptions

Only documentation files specifically targeting non-English audiences may use other languages, but those should be clearly marked and separated from the main codebase documentation.

## Enforcement

Please ensure all contributions follow this guideline. Code reviews will check for compliance with this rule.

## Git Repository Location

The oatcheck project is part of the ART (Android Runtime) repository, located at:

```
/ssd2/wyz/AOSP/art/
```

## Building oatcheck

To compile oatcheck, use:
```bash
cd /ssd2/wyz/AOSP && source ./setenv-tokay.sh && m oatcheck
```
## Test artifacts
A program depends on Android runtime needs to run on host with `art_host.py`. This py script fills all params essential for android runtime. 
### Testing oatcheck

To test oatcheck, just pick an app in /ssd2/wyz/app_oats. Each directory represents an app, base.apk is the app apk, and odex files are located in oat subdir

Use oatcheck/oatcheck_host.py to run oatcheck:
```bash
oatcheck/oatcheck_host.py [args of oatcheck]
```

For example:

a. test oatcheck with app
```
# in dir art/...
python3 oatcheck/oatcheck_host.py --apk=/ssd2/wyz/app_oats/15.0.0_r3/com.tencent.mm/base.apk --oat=/ssd2/wyz/app_oats/15.0.0_r3/com.tencent.mm/oat/base.odex  --origin-bcp-prefix=/ssd2/wyz/bcp_classes/15r3 --updated-bcp-prefix=/ssd2/wyz/bcp_classes/15r5
```
b. test oatcheck with app fix file as base.odexfixed
```
# in dir art/...
python3 oatcheck/oatcheck_host.py --apk=/ssd2/wyz/app_oats/com.tencent.mm/base.apk --oat=/ssd2/wyz/app_oats/com.tencent.mm/oat/base.odex  --origin-bcp-prefix=/ssd2/wyz/bcp_classes/15r3 --updated-bcp-prefix=/ssd2/wyz/bcp_classes/15r5 --fix
```
### Testing test_fix_validation
#### Compile: cd /ssd2/wyz/AOSP && source ./setenv-tokay.sh && m test_fix_validation
#### use: python3 oatcheck/test_fix_validation_host.py --fixed-oat=/ssd2/wyz/app_oats/15.0.0_r5/com.tencent.mm/oat/base.odex --original-oat=/ssd2/wyz/app_oats/15.0.0_r3/com.tencent.mm/oat/base.odex --compare-code
## 常见错误（重要）
### Dont remove include statements of include xxx-inl.h
If mcp tells u some of xxx-inl.h never been used, dont care. It is a false positive.
### 不要重复已有的代码，尽可能复用现有代码
### 如果你不知道要做什么，问用户，别猜