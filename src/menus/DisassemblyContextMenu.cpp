#include "DisassemblyContextMenu.h"
#include "dialogs/AsmOptionsDialog.h"
#include "dialogs/CommentsDialog.h"
#include "dialogs/FlagDialog.h"
#include "dialogs/RenameDialog.h"
#include "dialogs/XrefsDialog.h"
#include <QtCore>
#include <QShortcut>

DisassemblyContextMenu::DisassemblyContextMenu(QWidget *parent)
    :   QMenu(parent),
        offset(0),
        actionAddComment(this),
        actionAddFlag(this),
        actionRename(this),
        actionRenameUsedHere(this),
        actionXRefs(this),
        actionDisplayOptions(this),
        actionSetBaseBinary(this),
        actionSetBaseOctal(this),
        actionSetBaseDecimal(this),
        actionSetBaseHexadecimal(this),
        actionSetBasePort(this),
        actionSetBaseIPAddr(this),
        actionSetBaseSyscall(this),
        actionSetBaseString(this)
{
    actionAddComment.setText(tr("Add Comment"));
    this->addAction(&actionAddComment);
    actionAddComment.setShortcut(getCommentSequence());

    actionAddFlag.setText(tr("Add Flag"));
    this->addAction(&actionAddFlag);
    actionAddFlag.setShortcut(getAddFlagSequence());

    actionRename.setText(tr("Rename"));
    this->addAction(&actionRename);
    actionRename.setShortcut(getRenameSequence());

    actionRenameUsedHere.setText(("Rename Flag/Fcn/Var Used Here"));
    this->addAction(&actionRenameUsedHere);
    actionRenameUsedHere.setShortcut(getRenameUsedHereSequence());

    setBaseMenu = new QMenu(tr("Set Immediate Base to..."), this);
    setBaseMenuAction = addMenu(setBaseMenu);
    actionSetBaseBinary.setText(tr("Binary"));
    setBaseMenu->addAction(&actionSetBaseBinary);
    actionSetBaseOctal.setText(tr("Octal"));
    setBaseMenu->addAction(&actionSetBaseOctal);
    actionSetBaseDecimal.setText(tr("Decimal"));
    setBaseMenu->addAction(&actionSetBaseDecimal);
    actionSetBaseHexadecimal.setText(tr("Hexadecimal"));
    setBaseMenu->addAction(&actionSetBaseHexadecimal);
    actionSetBasePort.setText(tr("Network Port"));
    setBaseMenu->addAction(&actionSetBasePort);
    actionSetBaseIPAddr.setText(tr("IP Address"));
    setBaseMenu->addAction(&actionSetBaseIPAddr);
    actionSetBaseSyscall.setText(tr("Syscall"));
    setBaseMenu->addAction(&actionSetBaseSyscall);
    actionSetBaseString.setText(tr("String"));
    setBaseMenu->addAction(&actionSetBaseString);

    this->addSeparator();
    actionXRefs.setText(tr("Show X-Refs"));
    this->addAction(&actionXRefs);
    actionXRefs.setShortcut(getXRefSequence());

    this->addSeparator();
    actionDisplayOptions.setText(tr("Show Options"));
    actionDisplayOptions.setShortcut(getDisplayOptionsSequence());
    this->addAction(&actionDisplayOptions);

    auto pWidget = parentWidget();

#define ADD_SHORTCUT(sequence, slot) { \
    QShortcut *shortcut = new QShortcut((sequence), pWidget); \
    shortcut->setContext(Qt::WidgetWithChildrenShortcut); \
    connect(shortcut, &QShortcut::activated, this, (slot)); \
}
    ADD_SHORTCUT(getDisplayOptionsSequence(), &DisassemblyContextMenu::on_actionDisplayOptions_triggered);
    ADD_SHORTCUT(getXRefSequence(), &DisassemblyContextMenu::on_actionXRefs_triggered);
    ADD_SHORTCUT(getCommentSequence(), &DisassemblyContextMenu::on_actionAddComment_triggered);
    ADD_SHORTCUT(getAddFlagSequence(), &DisassemblyContextMenu::on_actionAddFlag_triggered);
    ADD_SHORTCUT(getRenameSequence(), &DisassemblyContextMenu::on_actionRename_triggered);
    ADD_SHORTCUT(getRenameUsedHereSequence(), &DisassemblyContextMenu::on_actionRenameUsedHere_triggered);
#undef ADD_SHORTCUT

    connect(&actionAddComment, SIGNAL(triggered(bool)), this, SLOT(on_actionAddComment_triggered()));
    connect(&actionAddFlag, SIGNAL(triggered(bool)), this, SLOT(on_actionAddFlag_triggered()));
    connect(&actionRename, SIGNAL(triggered(bool)), this, SLOT(on_actionRename_triggered()));
    connect(&actionRenameUsedHere, SIGNAL(triggered(bool)), this, SLOT(on_actionRenameUsedHere_triggered()));
    connect(&actionXRefs, SIGNAL(triggered(bool)), this, SLOT(on_actionXRefs_triggered()));
    connect(&actionDisplayOptions, SIGNAL(triggered()), this, SLOT(on_actionDisplayOptions_triggered()));

    connect(&actionSetBaseBinary, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseBinary_triggered()));
    connect(&actionSetBaseOctal, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseOctal_triggered()));
    connect(&actionSetBaseDecimal, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseDecimal_triggered()));
    connect(&actionSetBaseHexadecimal, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseHexadecimal_triggered()));
    connect(&actionSetBasePort, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBasePort_triggered()));
    connect(&actionSetBaseIPAddr, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseIPAddr_triggered()));
    connect(&actionSetBaseSyscall, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseSyscall_triggered()));
    connect(&actionSetBaseString, SIGNAL(triggered(bool)), this, SLOT(on_actionSetBaseString_triggered()));

    connect(this, SIGNAL(aboutToShow()), this, SLOT(aboutToShowSlot()));
}

void DisassemblyContextMenu::setOffset(RVA offset)
{
    this->offset = offset;
}

void DisassemblyContextMenu::aboutToShowSlot()
{
    // check if set immediate base menu makes sense
    QJsonObject instObject = Core()->cmdj("aoj @ " + QString::number(offset)).array().first().toObject();
    auto keys = instObject.keys();
    bool immBase = keys.contains("val") || keys.contains("ptr");
    setBaseMenuAction->setVisible(immBase);

    // only show "rename X used here" if there is something to rename
    QString thingUsedHere = Core()->cmd("an @ " + QString::number(offset)).trimmed();
    if (!thingUsedHere.isEmpty())
    {
        actionRenameUsedHere.setVisible(true);
        actionRenameUsedHere.setText(tr("Rename \"%1\" (used here)").arg(thingUsedHere));
    }
    else
    {
        actionRenameUsedHere.setVisible(false);
    }
}

QKeySequence DisassemblyContextMenu::getCommentSequence() const
{
    return {";"};
}

QKeySequence DisassemblyContextMenu::getAddFlagSequence() const
{
    return {}; //TODO insert correct sequence
}

QKeySequence DisassemblyContextMenu::getRenameSequence() const
{
    return {Qt::Key_N};
}

QKeySequence DisassemblyContextMenu::getRenameUsedHereSequence() const
{
    return {Qt::SHIFT + Qt::Key_N};
}

QKeySequence DisassemblyContextMenu::getXRefSequence() const
{
    return {Qt::Key_X};
}

QKeySequence DisassemblyContextMenu::getDisplayOptionsSequence() const
{
    return {}; //TODO insert correct sequence
}

void DisassemblyContextMenu::on_actionAddComment_triggered()
{
    RAnalFunction *fcn = Core()->functionAt(offset);
    CommentsDialog *c = new CommentsDialog(this);
    if (c->exec())
    {
        QString comment = c->getComment();
        Core()->setComment(offset, comment);
        if (fcn)
        {
            Core()->seek(fcn->addr);
        }
    }
}

void DisassemblyContextMenu::on_actionAddFlag_triggered()
{
    FlagDialog *dialog = new FlagDialog(offset, this->parentWidget());
    dialog->exec();
}

void DisassemblyContextMenu::on_actionRename_triggered()
{
    ut64 tgt_addr = UT64_MAX;
    RAnalOp op;
    RCore *core = Core()->core();

    RenameDialog *dialog = new RenameDialog(this);

    r_anal_op(core->anal, &op, offset, core->block + offset - core->offset, 32);
    tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
    if (op.var) {
        RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, offset, 0);
        if (fcn) {
            RAnalVar *bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
            if (!bar) {
                bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
                if (!bar) {

                    bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
                }
            }
            if (bar) {
                dialog->setName(bar->name);
                if (dialog->exec()) {
                    QString new_name = dialog->getName();
                    r_anal_var_rename (core->anal, fcn->addr, bar->scope,
                        bar->kind, bar->name, new_name.toStdString().c_str());
                }
            }
        }
    } else if (tgt_addr != UT64_MAX) {
        RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, tgt_addr, R_ANAL_FCN_TYPE_NULL);
        RFlagItem *f = r_flag_get_i (core->flags, tgt_addr);
        if (fcn) {
            /* Rename function */
            dialog->setName(fcn->name);
            if (dialog->exec()) {
                QString new_name = dialog->getName();
                Core()->renameFunction(fcn->name, new_name);
            }
        } else if (f) {
            /* Rename current flag */
            dialog->setName(f->name);
            if (dialog->exec()) {
                QString new_name = dialog->getName();
                Core()->renameFlag(f->name, new_name);
            }
        } else {
            /* Create new flag */
            dialog->setName("");
            if (dialog->exec()) {
                QString new_name = dialog->getName();
                Core()->addFlag(tgt_addr, new_name, 1);
            }
        }
    }
    r_anal_op_fini (&op);
    emit Core()->commentsChanged();
}

void DisassemblyContextMenu::on_actionRenameUsedHere_triggered()
{
    QString thingUsedHere = Core()->cmd("an @ " + QString::number(offset)).trimmed();
    if (thingUsedHere.isEmpty())
    {
        return;
    }

    RenameDialog *dialog = new RenameDialog(this);
    dialog->setWindowTitle(tr("Rename %1").arg(thingUsedHere));
    dialog->setName(thingUsedHere);
    if (dialog->exec()) {
        QString new_name = dialog->getName();
        Core()->cmd("an " + new_name.trimmed() + " @ " + QString::number(offset));
    }
}

void DisassemblyContextMenu::on_actionXRefs_triggered()
{
    XrefsDialog *dialog = new XrefsDialog(this);
    dialog->fillRefsForAddress(offset, RAddressString(offset), false);
    dialog->exec();
}

void DisassemblyContextMenu::on_actionDisplayOptions_triggered()
{
    AsmOptionsDialog *dialog = new AsmOptionsDialog(this->parentWidget());
    dialog->show();
}

void DisassemblyContextMenu::on_actionSetBaseBinary_triggered()
{
    Core()->setImmediateBase("b", offset);
}

void DisassemblyContextMenu::on_actionSetBaseOctal_triggered()
{
    Core()->setImmediateBase("o", offset);
}

void DisassemblyContextMenu::on_actionSetBaseDecimal_triggered()
{
    Core()->setImmediateBase("d", offset);
}

void DisassemblyContextMenu::on_actionSetBaseHexadecimal_triggered()
{
    Core()->setImmediateBase("h", offset);
}

void DisassemblyContextMenu::on_actionSetBasePort_triggered()
{
    Core()->setImmediateBase("p", offset);
}

void DisassemblyContextMenu::on_actionSetBaseIPAddr_triggered()
{
    Core()->setImmediateBase("i", offset);
}

void DisassemblyContextMenu::on_actionSetBaseSyscall_triggered()
{
    Core()->setImmediateBase("S", offset);
}

void DisassemblyContextMenu::on_actionSetBaseString_triggered()
{
    Core()->setImmediateBase("s", offset);
}
