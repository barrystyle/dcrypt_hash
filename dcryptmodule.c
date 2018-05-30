#include <Python.h>

#include "dcrypt.h"

static PyObject *dcrypt_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    dcrypt_hash((char *)PyBytes_AsString((PyObject*) input), output, 80);
#else
    dcrypt_hash((char *)PyString_AsString((PyObject*) input), output, 80);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef dcryptMethods[] = {
    { "getPoWHash", dcrypt_getpowhash, METH_VARARGS, "Returns the proof of work hash using dcrypt" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef dcryptModule = {
    PyModuleDef_HEAD_INIT,
    "dcrypt_hash",
    "...",
    -1,
    dcryptMethods
};

PyMODINIT_FUNC PyInit_dcrypt_hash(void) {
    return PyModule_Create(&dcryptModule);
}

#else

PyMODINIT_FUNC initdcrypt_hash(void) {
    (void) Py_InitModule("dcrypt_hash", dcryptMethods);
}
#endif
