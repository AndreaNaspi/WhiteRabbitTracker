#include "itree.h"
#include <iostream>

// most of the following code is a reworked and extended
// version of https://github.com/Frky/iCi (ACSAC'18)

/* ===================================================================== */
/* Initialization function to create the interval tree                   */
/* ===================================================================== */
itreenode_t *itree_init(ADDRINT start_addr, ADDRINT end_addr, void *data) {
	// Allocate memory
	itreenode_t *tree = (itreenode_t *)malloc(sizeof(itreenode_t));
	// Populate initial data in the interval tree
	tree->start_addr = start_addr;
	tree->end_addr = end_addr;
	tree->data = data;
	tree->left = NULL;
	tree->right = NULL;
	// Return an empty interval tree
	return tree;
}

/* ===================================================================== */
/* Function to insert left/right node in the interval tree               */
/* ===================================================================== */
bool itree_insert(itreenode_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data) {
	// Get the current interval tree
	itreenode_t *senti = tree;

	// Insert a duplicate node, return false
	if (senti->start_addr == start_addr && senti->end_addr == end_addr)
		return false;
	// Insert in the right subtree
	else if (senti->end_addr < start_addr) {
		// Check if the right subtree exists. If the right subtree exist, add the node data (recursive call until leaf)
		if (senti->right) {
			return itree_insert(senti->right, start_addr, end_addr, data);
		}
		// If the right subtree not exists, initialize it with the new node data
		else {
			senti->right = itree_init(start_addr, end_addr, data);
			return true;
		}
	}
	// Insert in the left subtree
	else {
		// Check if the left subtree exists. If the left subtree exist, add the node data (recursive call until leaf)
		if (senti->left) {
			return itree_insert(senti->left, start_addr, end_addr, data);
		}
		// If the left subtree not exists (leaf found), initialize it with the new node data
		else {
			senti->left = itree_init(start_addr, end_addr, data);
			return true;
		}
	}
	return false;
}

/* ===================================================================== */
/* Function to delete a node in the interval tree                        */
/* ===================================================================== */
itreenode_t* itree_delete(itreenode_t* tree, ADDRINT start_addr, ADDRINT end_addr) {
	// Base case
	if (tree == NULL) {
		return NULL;
	}

	// Requested node found
	if (tree->start_addr == start_addr && tree->end_addr == end_addr) {
		itreenode_t* tmp;
		// Check if the node don't have left child
		if (tree->left == NULL) { 
			tmp = tree->right;
			free(tree);
			return tmp;
		}
		// Check if the node don't have right child
		else if (tree->right == NULL) {
			tmp = tree->left;
			free(tree);
			return tmp;
		}
		// Node have some children! 
		// find leftmost descendant in right subtree and paste it into the current node, then remove it
		else {
			tmp = tree->right;
			while (tmp && tmp->left) tmp = tmp->left;
			tree->start_addr = tmp->start_addr;
			tree->end_addr = tmp->end_addr;
			tree->data = tmp->data;
			tree->right = itree_delete(tree->right, tmp->start_addr, tmp->end_addr);
		}
	}
	// Search requested node in the right subtree (recursive call)
	else if (tree->end_addr < start_addr) { 
		tree->right = itree_delete(tree->right, start_addr, end_addr);
	}
	// Search requested node in the left subtree (recursive call)
	else { 
		tree->left = itree_delete(tree->left, start_addr, end_addr);
	}
	// Return the tree with a deleted node
	return tree;
}

/* ===================================================================== */
/* Function to search a node in the interval tree                        */
/* ===================================================================== */
itreenode_t *itree_search(itreenode_t *tree, ADDRINT val) {
	// If the tree not exists, return null (base case)
	if (!tree) {
		return NULL;
	}
	// Get the current interval tree
	itreenode_t *senti = tree;

	// Requested address found in the current node
	if (val >= senti->start_addr && val <= senti->end_addr) {
		return senti;
	}
	// Search the requested address in the right subtree (recursive call)
	else if (senti->end_addr < val) {
		if (senti->right)
			return itree_search(senti->right, val);
		else
			return NULL;
	}
	// Search the requested address in the left subtree (recursive call)
	else {
		if (senti->left)
			return itree_search(senti->left, val);
		else
			return NULL;
	}
	return NULL;
}

/* ===================================================================== */
/* Function to verify the current interval tree                          */
/* ===================================================================== */
bool itree_verify(itreenode_t *tree) {
	// If the tree not exists, return null (base case)
	if (!tree) {
		return true;
	}

	// Well-formed interval
	if (tree->end_addr <= tree->start_addr) 
		return false;

	// Left child contains interval ending beyond the parent interval's start
	if (tree->left && tree->left->end_addr >= tree->start_addr) 
		return false;

	// Right child contains interval starting before the parent interval's end
	if (tree->right && tree->right->start_addr <= tree->end_addr) 
		return false;

	// Recursive call to verify all the interval tree nodes
	return (itree_verify(tree->left) && itree_verify(tree->right));
}

/* ===================================================================== */
/* Function to print the current interval tree                           */
/* ===================================================================== */
void itree_print(itreenode_t *node, ADDRINT lvl) {
	// If the node not exists, return null (base case)
	if (!node) {
		return;
	}

	// Print che rurrent node with relevant level and range (start address and end address)
	fprintf(stderr, "Level: %u , Range: [0x%0x, 0x%0x]\n",
		lvl, node->start_addr, node->end_addr);

	// Recursive calls to print all the interval tree nodes
	itree_print(node->left, lvl + 1);
	itree_print(node->right, lvl + 1);
	return;
}

/* ===================================================================== */
/* Utility function to calculate the tree depth                          */
/* ===================================================================== */
UINT32 depth(itreenode_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + MAX(depth(tree->right), depth(tree->left));
}

/* ===================================================================== */
/* Utility function to the number of nodes in the tree                   */
/* ===================================================================== */
UINT32 nb_nodes(itreenode_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + nb_nodes(tree->right) + nb_nodes(tree->left);
}


/* ===================================================================== */
/* Function to obtain statistics from the current interval tree          */
/* ===================================================================== */
VOID itree_stats(itreenode_t *node) {
	std::cerr << "NODES: " << nb_nodes(node) << std::endl;
	std::cerr << "DEPTH: " << depth(node) << std::endl;
	return;
}

/* ===================================================================== */
/* Function to de-allocate the interval tree structure from memory       */
/* ===================================================================== */
BOOL itree_dealloc(itreenode_t* tree) {
	if (!tree)
		return true;

	itreenode_t *senti = tree;
	itreenode_t *right = tree->right;
	itreenode_t *left = tree->left;
	free(tree); // TODO memory leak on data

	if (right) {
		itree_dealloc(right);
	}
	if (left) {
		itree_dealloc(left);
	}

	return true;
}