usdt::new {
    printf("{\"addr\": \"%p\", \"event\": \"new\"}\n", arg0);
}
usdt::free {
    printf("{\"addr\": \"%p\", \"event\": \"free\"}\n", arg0);
}
usdt::client_random {
    printf("{\"addr\": \"%p\", \"event\": \"client_random\"", arg0);
    printf(", \"bytes\": \"%s\"}\n", str(arg1));
}
usdt::new_secret {
    printf("\"addr\": \"%p\", \"event\": \"new_secret\"", arg0);
    printf(", \"label\": \"%s\", \"secret\": \"%s\"}\n", str(arg1), str(arg2));
}
