package p2

# should not be called from p1 policy
v1 := v {
    input.color == "blue"
    v := 1
}

v2[v] {
    input.color == "blue"
    v := 2
}

v2[v] {
    input.color == "blue"
    v := 3
}
