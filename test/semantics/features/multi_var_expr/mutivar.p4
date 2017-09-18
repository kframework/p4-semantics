parser start {
    return ingress;
}

action testA() {

}

table test {
    actions {
            testA;
    }
}

control ingress {
    if (1 + 1 > 2) {
        apply(test);
    }
}