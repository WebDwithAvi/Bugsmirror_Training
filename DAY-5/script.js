// Replace "libfoo.so" with the actual library name
var moduleName = 'libfoo.so';
//var strncmpAddress = Module.findExportByName(moduleName, 'strncmp');
// function onClick(){

// }

setTimeout(() => {
    Interceptor.attach(Module.findExportByName(moduleName, 'strncmp'),{
        onEnter:function(args){
            try {
                var v1 =Memory.readUtf8String(args[0])
                var v2 =Memory.readUtf8String(args[1])
                if(v1.includes("abcdefghijklmnopqrstuvw") || v2.includes("abcdefghijklmnopqrstuvw")){
                    console.log(v1,v2);
                }
                //console.log(Memory.readUtf8String(args));

            } catch (error) {
                console.error(error)
            }



            //console.log('strncmp called with:', str1, str2);

        },
        onLeave:function(retval){

        }

    });

}, 5000);
    