#pragma once

#include <map>
#include <iostream>
#include "pin.H"
#include "winheaders.h"

/* ===================================================================== */
/* Structure to store the DLLs interval tree                             */
/* ===================================================================== */
typedef struct itreenode {
	ADDRINT start_addr, end_addr;   // range [a, b]
	void *data;						// user-supplied data
	struct itreenode *left, *right;	// left and right children
} itreenode_t;

typedef struct {
	void* dllPath;
	std::map<W::DWORD, std::string> exports;
} monitoredDLL;

/* ===================================================================== */
/* Initialization function to create the interval tree                   */
/* ===================================================================== */
itreenode_t *itree_init(ADDRINT start_addr, ADDRINT end_addr, void* data);

/* ===================================================================== */
/* Function to insert left/right node in the interval tree               */
/* ===================================================================== */
bool itree_insert(itreenode_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data);

/* ===================================================================== */
/* Function to delete a node in the interval tree                        */
/* ===================================================================== */
itreenode_t* itree_delete(itreenode_t* tree, ADDRINT start_addr, ADDRINT end_addr);

/* ===================================================================== */
/* Function to search a node in the interval tree                        */
/* ===================================================================== */
itreenode_t *itree_search(itreenode_t *tree, ADDRINT val);

/* ===================================================================== */
/* Function to verify the current interval tree                          */
/* ===================================================================== */
bool itree_verify(itreenode_t *tree);

/* ===================================================================== */
/* Function to print the current interval tree                           */
/* ===================================================================== */
void itree_print(itreenode_t *node, ADDRINT lvl);

/* ===================================================================== */
/* Function to obtain statistics from the current interval tree          */
/* ===================================================================== */
VOID itree_stats(itreenode_t *node);

/* ===================================================================== */
/* Function to de-allocate the interval tree structure from memory       */
/* ===================================================================== */
BOOL itree_dealloc(itreenode_t* tree);