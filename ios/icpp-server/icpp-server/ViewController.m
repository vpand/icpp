//
//  ViewController.m
//  icpp-server
//
// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.
//

#import "ViewController.h"

static int pipeFD[2];

extern void start_icpp_server(const char *main_exe);

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
  
    // 1. Initialize UITextView
    self.logTextView = [[UITextView alloc] initWithFrame:self.view.bounds];
    
    // 2. Configure for read-only logging appearance
    self.logTextView.editable = NO;
    self.logTextView.selectable = YES;
    self.logTextView.font = [UIFont fontWithName:@"Menlo" size:12.0]; // Monospaced font for logs
    self.logTextView.backgroundColor = [UIColor whiteColor];
    self.logTextView.textColor = [UIColor blackColor];
    
    // 3. Enable Auto Layout
    self.logTextView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.logTextView];
    
    // 4. Pin to view edges
    [NSLayoutConstraint activateConstraints:@[
        [self.logTextView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.logTextView.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],
        [self.logTextView.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor],
        [self.logTextView.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor]
    ]];
    
    [self redirectStandardOutputAndError];
    
    start_icpp_server([[NSBundle mainBundle] executablePath].UTF8String);
}

- (void)redirectStandardOutputAndError {
    // Create a pipe
    if (pipe(pipeFD) != 0) {
        return;
    }

    // Redirect stdout (1) and stderr (2) to the write end of the pipe
    dup2(pipeFD[1], STDOUT_FILENO);
    dup2(pipeFD[1], STDERR_FILENO);

    // Disable line buffering so stdout appears immediately
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Read from the pipe in a background queue to avoid blocking UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char buffer[1024];
        ssize_t bytesRead;

        while ((bytesRead = read(pipeFD[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';
          
            NSString *chunk = [NSString stringWithUTF8String:buffer];
            if (!chunk) continue;

            // Split by newlines so each line is processed individually
            NSArray<NSString *> *lines = [chunk componentsSeparatedByString:@"\n"];
            for (NSString *line in lines) {
                if (line.length > 0) {
                    [self appendLog:line];
                }
            }
        }
    });
}

- (void)appendLog:(NSString *)logText {
    dispatch_async(dispatch_get_main_queue(), ^{
        // 1. Format current date & time
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"HH:mm:ss"];
        NSString *timestamp = [formatter stringFromDate:[NSDate date]];
        
        // 2. Combine timestamp and message
        NSString *formattedLog = [NSString stringWithFormat:@"[%@] %@\n", timestamp, logText];
        
        // 3. Append to log view
        self.logTextView.text = [self.logTextView.text stringByAppendingString:formattedLog];
        
        // 4. Auto-scroll to bottom
        NSRange range = NSMakeRange(self.logTextView.text.length - 1, 1);
        [self.logTextView scrollRangeToVisible:range];
    });
}

@end
