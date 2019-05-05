picotls$target:::new {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"new\", \"is_server\": %d}", arg0, arg1);
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
picotls$target:::receive_message {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"receive_message\", \"type\": %d, \"ret\": %d}\n", arg0, arg1, arg4);
    tracemem(copyin(arg2, arg3), 65535, arg3);
}
