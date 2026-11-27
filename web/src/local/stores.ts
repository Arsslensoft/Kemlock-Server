// Every module that keeps values sealed by the worker (`sealLocal`) and registers itself in
// `./registry` is imported here, so the app has them all before a rotation asks. Add a line when a
// new store is made.
import '@/spaces/anchors';
import '@/spaces/boxstore';
