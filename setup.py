from distutils.core import setup, Extension

dcrypt_hash_module = Extension('dcrypt_hash',
                                 sources = ['dcryptmodule.c',
                                            'dcrypt.c'],
                            include_dirs = ['.'],
                               libraries = ['crypto'])

setup (name = 'dcrypt_hash',
       version = '0.3',
       description = 'Dcrypt hashing module',
       ext_modules = [dcrypt_hash_module])
