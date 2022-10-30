`stdin`, `stdout`, and `stderr` are three data streams created when you launch a Linux command.

Data streams, like water streams, have two ends. They have a source and an outflow. Whichever Linux command you’re using provides one end of each stream. The other end is determined by the shell that launched the command. That end will be connected to the terminal window, connected to a pipe, or redirected to a file or other command, according to the command line that launched the command.

```bash
# ┌────┬────────────────────────────────────────┬─┐
# │BASH└────────────────────────────────────────┘X│                                      ┌────────────┐
# │                                               │                                      │            │
# │~> command │                                   │                                      │            │
# │           │                                   │                        ┌─┐           │            │
# │           │                                   │                      ┌─┼┼┼───────────┤ Source     │
# │           │                                   │                      └─┼┼────────────┤            │
# │           │ [1]                               │                        ││            │            │
# │           └───────────────────────────────────┼──────────────────────► └┘            │            │
# │                                               │                         ▼            │            │
# │                                               │                         ▼            │            │
# └───────────────────────────────────────────────┘                         ▼            │            │
#                                     ▲                                     ▼            │            │
#                                     │                                     ▼            │            │
#                                     │                                     ▼            │            │
#                                     │                                                  │            │
#                                     │       ┌──────────────────────────────────────┐   │            │
#                                     │[2]    │    <<  <  <<<<< < < < <<<            │   │            │
#          TO other place...  ◄ ──────└───────┤    <<<<     << <<<       <<<<<  <<   │   │            │
#                                             │  <<   <<< < <<<<<<<<<<<  <  <        │   │            │
#                                             │Sink    <  >>    >> <   >>   <<<>  <  │   │            │
#                                             │      <<  >>  >>>   <>>>>>>>>>><<  <  │   │            │
#                                             │    <<<>>> > > >  > <<<<<<<<<<<<<   < │   │            │
#                                             │   <<>>    >><<<< ><<<<<<<<< <<     < │   │            │
#                                             │    <<<<<<<<<    <<<<<<<<<<<<<<<<<<<< │   │            │
#                                             └──────────────────────────────────────┘   └────────────┘
```

- `stdin` is the standard input stream. This accepts text as its input.
- `stdout` is the standard output stream. Text output from the command to the shell is delivered via `stdout`.
- `stderr` is the standard error stream. Error messages from the command are sent through the `stderr`

Each file associated with a process is allocated a unique number to identify it. This is known as the file descriptor. Whenever an action is required to be performed on a file, [the file descriptor](https://en.wikipedia.org/wiki/File_descriptor) is used to identify the file.

These values are always used for `stdin`, `stdout,` and `stderr`:

- *0*: stdin
- *1*: stdout
- *2*: stderr

## Check Data Streams:

we can check the FD is opened in terminal with flag -t in `test` [ EXPRESSION ] command. `-t` (terminal) option returns true (0) if the file associated with the file descriptor [terminates in the terminal window](http://man7.org/linux/man-pages/man1/test.1.html).

for `stdin` , Type the following text into an editor and save it as [input.sh](./files/input.sh).

```bash
#!/bin/bash

if [ -t 0 ]; then

  echo stdin coming from keyboard
 
else

  echo stdin coming from a pipe or a file
 
fi
```

make it executable:

```bash
chmod +x input.sh
```

We can use any convenient text file to generate input to the script. 

```bash
./input.sh < test.txt
```

- ⇒ ‘stdin coming from a pipe or a file’

To check the same thing with the output stream:([output.sh](./files/output.sh))

```bash
#!/bin/bash

if [ -t 1 ]; then
        echo stdout is going to the terminal window
else
        echo stdout is being redirected or piped
fi
```

Also we need to executable it:

```bash
chmod +x ./output.sh
```

test outpush.sh:

```bash
./output.sh
```

- ⇒ echo stdout is going to the terminal window

```bash
./output.sh | cat
```

- ⇒ stdout is being redirected or piped

```bash
 ./output.sh > /tmp/test4
 cat /tmp/test4
```

- ⇒ stdout is being redirected or piped

### Reference:

- [HTG](https://www.howtogeek.com/435903/what-are-stdin-stdout-and-stderr-on-linux/)
