picotls$target:::new {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"new\"}", arg0);
}
picotls$target:::free {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"free\"}", arg0);
}
picotls$target:::client_random {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"client_random\", \"bytes\": \"%s\"}", arg0, copyinstr(arg1));
}
picotls$target:::new_secret {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"new_secret\", \"label\": \"%s\", \"secret\": \"%s\"}", arg0, copyinstr(arg1), copyinstr(arg2));
}
