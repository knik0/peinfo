CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -s
DEFS =
INCLUDE=
TARGET=peinfo
OBJS =
#LIBS := $(LIBS)

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

#$(TARGET): $(OBJS)
#	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

%: %.c
	$(CC) -o $@ $(DEFS) $(INCLUDE) ${CFLAGS} $(LDFLAGS) $(OBJS) $< $(LIBS)

%.o: %.c
	${CC} -c $(DEFS) $(INCLUDE) ${CFLAGS} $<

%.o: %.cpp
	${CC} -c $(DEFS) $(INCLUDE) ${CFLAGS} $<

%.o: %.s
	gcc -x assembler-with-cpp -c $(DEFS) $< -o $@

#${RC} --include-dir $(WIZDIR) $< $@

%.ro: %.rc
	${RC} --define WIN32 --define __MINGW32__ --define NDEBUG --include-dir . $< $@

