#ifndef GRAPHWIDGET_H
#define GRAPHWIDGET_H

#include "CutterDockWidget.h"

class MainWindow;
class DisassemblerGraphView;

class GraphWidget : public CutterDockWidget
{
    Q_OBJECT

public:
    explicit GraphWidget(MainWindow *main, QAction *action = nullptr);
    ~GraphWidget() override;

private:
    DisassemblerGraphView *graphView;

    void refreshContent() override;

};

#endif // GRAPHWIDGET_H
