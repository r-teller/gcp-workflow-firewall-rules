# Define package name
package common

# remove_duplicates removes duplicate elements from a given list.
# It uses a set to eliminate duplicates and then converts the set back to a list.
#
# Parameters:
# - list: The input list that may contain duplicate elements.
#
# Returns:
# - unique_list: A new list containing only unique elements from the input list.
remove_duplicates(list) = unique_list {
    # Create a set from the input list to remove duplicates
    unique_set := {x | x := list[_]}
    # Convert the set back to a list
    unique_list := [x | x := unique_set[_]]
}

# list_contains checks if a given element is present in an array.
#
# Parameters:
# - array: The input array to search in.
# - element: The element to search for in the array.
#
# Returns:
# - Boolean: True if the element is found in the array, false otherwise.
list_contains(array, element) {
    some i
    array[i] == element
}